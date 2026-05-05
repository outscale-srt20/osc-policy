package lib.modules

import rego.v1

# all_resources — ensemble de toutes les ressources du plan, y compris les
# ressources imbriquées dans child_modules. Utilise la fonction built-in
# walk() pour éviter la récursion utilisateur (interdite par Rego).
all_resources contains resource if {
    some path, value
    walk(input.planned_values, [path, value])
    # On ne retient que les tableaux "resources" des modules.
    path[count(path) - 1] == "resources"
    is_array(value)
    some resource in value
    is_terraform_resource(resource)
}

is_terraform_resource(r) if {
    is_object(r)
    r.type
    r.address
}

# live_resources — ressources provenant d'un snapshot live.
live_resources contains r if {
    some r in input.resources
}

# resources_of_type — union plan + live pour un type donné.
resources_of_type(t) := out if {
    plan := [r | some r in all_resources; r.type == t]
    live := [r | some r in live_resources; r.type == t]
    out := array.concat(plan, live)
}
