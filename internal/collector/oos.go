package collector

import (
	"context"
	"errors"
	"fmt"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	osc "github.com/outscale/osc-sdk-go/v2"
)

// OOS collector — OOS (Object Outscale Storage) is S3-compatible.
// Auth via the same AK/SK as osc-sdk, but a separate AWS S3 client targeting
// the OOS endpoint (oos.<region>.outscale.com).
//
// For each bucket, the collector fetches a baseline of attributes that
// matter for security/compliance rules:
//   - ACL (private vs public)
//   - Versioning
//   - Lifecycle configuration (presence)
//   - Logging
//   - Bucket policy (raw JSON, for rules looking for Principal "*")
//   - Tagging
//
// API calls returning errors other than "no such config" are captured into
// Values["_collector_errors"] for visibility, without aborting the collect.
type OOS struct{}

func (OOS) Name() string { return "oos" }

func (OOS) Collect(ctx context.Context, _ *osc.APIClient) ([]Resource, error) {
	awsv4Val := ctx.Value(osc.ContextAWSv4)
	if awsv4Val == nil {
		return nil, fmt.Errorf("OOS collector: AWSv4 credentials missing from context")
	}
	awsv4, ok := awsv4Val.(osc.AWSv4)
	if !ok {
		return nil, fmt.Errorf("OOS collector: unexpected ContextAWSv4 type")
	}

	region := "eu-west-2"
	if vars, ok := ctx.Value(osc.ContextServerVariables).(map[string]string); ok {
		if r := vars["region"]; r != "" {
			region = r
		}
	}

	endpoint := fmt.Sprintf("https://oos.%s.outscale.com", region)

	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(awsv4.AccessKey, awsv4.SecretKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("OOS aws config: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = &endpoint
		o.UsePathStyle = true
	})

	listResp, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("OOS ListBuckets: %w", err)
	}

	out := make([]Resource, 0, len(listResp.Buckets))

	for _, b := range listResp.Buckets {
		if b.Name == nil || *b.Name == "" {
			continue
		}
		name := *b.Name
		out = append(out, collectBucket(ctx, client, name, b.CreationDate))
	}

	return out, nil
}

func collectBucket(ctx context.Context, client *s3.Client, name string, creationDate interface{}) Resource {
	values := map[string]interface{}{
		"bucket":        name,
		"creation_date": creationDate,
	}
	errs := []string{}

	if aclResp, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &name}); err == nil {
		values["acl"] = aclSummary(aclResp.Grants)
		values["grants"] = grantsToMap(aclResp.Grants)
		values["public_via_acl"] = isAclPublic(aclResp.Grants)
	} else {
		errs = appendIfErr(errs, "GetBucketAcl", err)
	}

	if vResp, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: &name}); err == nil {
		values["versioning_enabled"] = string(vResp.Status) == "Enabled"
		values["versioning_status"] = string(vResp.Status)
	} else {
		errs = appendIfErr(errs, "GetBucketVersioning", err)
	}

	// GetBucketLogging is not implemented on Outscale OOS (501). Skip silently:
	// logging on OOS is handled differently (server-side telemetry, not S3 API).
	values["logging_supported"] = false

	if _, err := client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: &name}); err == nil {
		values["lifecycle_configured"] = true
	} else {
		values["lifecycle_configured"] = false
		if !isNoSuchLifecycleConfig(err) {
			errs = appendIfErr(errs, "GetBucketLifecycle", err)
		}
	}

	if pResp, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &name}); err == nil && pResp.Policy != nil {
		values["policy_document"] = *pResp.Policy
		values["policy_public"] = policyAllowsPublic(*pResp.Policy)
	} else if err != nil && !isNoSuchBucketPolicy(err) {
		errs = appendIfErr(errs, "GetBucketPolicy", err)
	}

	if tResp, err := client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: &name}); err == nil {
		tagsMap := map[string]string{}
		for _, t := range tResp.TagSet {
			if t.Key != nil && t.Value != nil {
				tagsMap[*t.Key] = *t.Value
			}
		}
		values["tags"] = tagsMap
	} else if !isNoSuchTagSet(err) {
		errs = appendIfErr(errs, "GetBucketTagging", err)
	}

	if len(errs) > 0 {
		values["_collector_errors"] = errs
	}

	return Resource{
		Type:    "outscale_oos",
		ID:      name,
		Address: name,
		Values:  values,
	}
}

// ---- helpers ----

func isAclPublic(grants []types.Grant) bool {
	for _, g := range grants {
		if g.Grantee == nil || g.Grantee.URI == nil {
			continue
		}
		uri := *g.Grantee.URI
		if strings.Contains(uri, "AllUsers") || strings.Contains(uri, "AuthenticatedUsers") {
			return true
		}
	}
	return false
}

func aclSummary(grants []types.Grant) string {
	if isAclPublic(grants) {
		return "public"
	}
	return "private"
}

func grantsToMap(grants []types.Grant) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(grants))
	for _, g := range grants {
		entry := map[string]interface{}{
			"permission": string(g.Permission),
		}
		if g.Grantee != nil {
			if g.Grantee.URI != nil {
				entry["uri"] = *g.Grantee.URI
			}
			if g.Grantee.ID != nil {
				entry["id"] = *g.Grantee.ID
			}
			entry["type"] = string(g.Grantee.Type)
		}
		out = append(out, entry)
	}
	return out
}

// policyAllowsPublic detects "Principal":"*" (or AWS:"*") in an Allow Statement.
// Heuristic — fine-grained analysis is delegated to Rego rules via policy_document.
func policyAllowsPublic(policy string) bool {
	if !strings.Contains(policy, "\"Allow\"") {
		return false
	}
	patterns := []string{
		`"Principal":"*"`,
		`"Principal": "*"`,
		`"Principal":{"AWS":"*"}`,
		`"Principal": {"AWS": "*"}`,
		`"AWS":["*"]`,
		`"AWS": ["*"]`,
	}
	for _, p := range patterns {
		if strings.Contains(policy, p) {
			return true
		}
	}
	return false
}

func isNoSuchLifecycleConfig(err error) bool {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode() == "NoSuchLifecycleConfiguration"
	}
	return false
}

func isNoSuchBucketPolicy(err error) bool {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode() == "NoSuchBucketPolicy"
	}
	return false
}

func isNoSuchTagSet(err error) bool {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode() == "NoSuchTagSet"
	}
	return false
}

func appendIfErr(errs []string, op string, err error) []string {
	if err == nil {
		return errs
	}
	return append(errs, fmt.Sprintf("%s: %v", op, err))
}
