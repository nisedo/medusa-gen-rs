// SPDX-License-Identifier: {{ licence }}
pragma solidity {{ solc }};

{{ imports }}
{% if is_abstract %}abstract {% endif %}contract {{ name }} {% if parents != "" %}is {{parents}} {% endif %}{
{{ body }}
}
