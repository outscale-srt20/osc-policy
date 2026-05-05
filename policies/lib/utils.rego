package lib.utils

import rego.v1

# has_field — true si obj contient un champ non vide.
has_field(obj, field) if {
    obj[field]
    not is_empty(obj[field])
}

is_empty(v) if v == null
is_empty(v) if v == ""
is_empty(v) if {
    is_array(v)
    count(v) == 0
}
is_empty(v) if {
    is_object(v)
    count(v) == 0
}

# is_public_cidr — couvre Internet public.
is_public_cidr(cidr) if cidr == "0.0.0.0/0"
is_public_cidr(cidr) if cidr == "::/0"

# get_tag récupère la valeur du tag (tags = array de {key,value}).
get_tag(tags, key) := v if {
    some i
    tags[i].key == key
    v := tags[i].value
}

has_tag(tags, key) if {
    some i
    tags[i].key == key
    tags[i].value != ""
}

# sensitive_ports — set des ports considérés comme sensibles.
sensitive_ports := {"22", "3389", "5432", "3306", "6379", "27017", "9200", "1433"}

to_number_safe(v) := n if {
    is_number(v)
    n := v
}
to_number_safe(v) := n if {
    is_string(v)
    n := to_number(v)
}
to_number_safe(v) := 0 if {
    not is_number(v)
    not is_string(v)
}

# required_tags — liste des tags obligatoires en mode compliance.
required_tags := ["Name", "Env", "Project", "Owner", "CostCenter"]
