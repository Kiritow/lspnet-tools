import json
from datetime import datetime
from typing import Dict, Any
from .config_types import CommonOSPFConfig, BFDConfig
from .utils import get_git_version


BIRD_CONFIG_TEMPLATE = '''# Auto generated by lspnet-tools at #CURRENT_TIME#
# version: #GIT_VERSION#

#LOCALNET_NO_IMPORT#
#LOCALNET_NO_EXPORT#

log stderr all;

#ROUTER_ID#

#debug protocols all;

protocol device {

}

protocol bfd {
    #BFD_PROTOCOL#
}

protocol direct {
    ipv4;
    #DIRECT_PROTOCOL#
}

protocol kernel {
    ipv4 {
        import none;
        export where proto = "wg";
    };
}

protocol ospf v2 wg {
    ecmp yes;
    merge external yes;
    ipv4 {
        #OSPF_IMPORT_FILTER#;
        #OSPF_EXPORT_FILTER#;
    };
    
    #OSPF_AREA_CONFIG#
}
'''


def render_config(template: str, params: Dict[str, Any]):
    content = template
    while True:
        new_content = content
        for key, value in params.items():
            new_content = new_content.replace('#{}#'.format(key), str(value))
        if new_content == content:
            return new_content
        content = new_content


def simple_format(content):
    output = []
    level = 0

    for line in content.split('\n'):
        sline = line.strip()
        if sline.startswith('#'):
            output.append(sline)
            continue
        if sline.startswith('}'):
            level = max(0, level - 1)
        output.append('  ' * level + sline)
        if sline.endswith('{'):
            level += 1

    return '\n'.join(output)


def get_bird_config(router_id, direct_interface_names, ospf_exclude_import_cidrs, ospf_exclude_export_cidrs, ospf_area_config: Dict[str, Dict[str, CommonOSPFConfig]], bfd_config: Dict[str, BFDConfig], is_dynamic=False):
    current_time_text = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    router_id_text = 'router id {};'.format(router_id) if router_id else ''
    dnames_text = '\n'.join(['interface "{}";'.format(name) for name in direct_interface_names])
    localnet_no_import_variable_text = 'define LOCALNET_NO_IMPORTSET=[{}];'.format(','.join(ospf_exclude_import_cidrs)) if ospf_exclude_import_cidrs else ''
    localnet_no_export_variable_text = 'define LOCALNET_NO_EXPORTSET=[{}];'.format(','.join(ospf_exclude_export_cidrs)) if ospf_exclude_export_cidrs else ''
    import_filter_text = '''import filter {
if net !~ LOCALNET_NO_IMPORTSET then accept;
else reject;
}''' if localnet_no_import_variable_text else 'import all'
    export_filter_text = '''export filter {
if net !~ LOCALNET_NO_EXPORTSET then accept;
else reject;
}''' if localnet_no_export_variable_text else 'export all'

    # OSPF
    all_area_texts = []
    for area_id, area_interface_mapping in ospf_area_config.items():
        text_parts = []
        text_parts.append(f'''area {area_id} {{''')
        for interface_name, ospf_interface_config in area_interface_mapping.items():
            text_parts.append(f'''interface "{interface_name}" {{''')
            if interface_name in bfd_config:
                text_parts.append("bfd yes;")
            if ospf_interface_config.cost or ospf_interface_config.pingcost:
                hint_tag = {"type": "cost", "raw": "cost {};", "skips": 1, "interface": interface_name, "pingcost": int(ospf_interface_config.pingcost)}
                text_parts.append('#HINT: {}'.format(json.dumps(hint_tag)))
                text_parts.append("cost {};".format(ospf_interface_config.cost or 500))
            if ospf_interface_config.type:
                text_parts.append("type {};".format(ospf_interface_config.type))
            if ospf_interface_config.auth:
                text_parts.append("authentication cryptographic;")
                text_parts.append(f'''password "{ospf_interface_config.auth}" {{
algorithm hmac sha512;
}};''')
            text_parts.append('};')
        text_parts.append('};')

        all_area_texts.append('\n'.join(text_parts))

    final_area_text = '\n'.join(all_area_texts)

    # BFD
    all_bfd_texts = []
    for interface_name, bfd_interface_config in bfd_config.items():
        text_parts = []
        text_parts.append(f'''interface "{interface_name}" {{''')
        if bfd_interface_config.rxMs or bfd_interface_config.intervalMs:
            text_parts.append(f'''min rx interval {bfd_interface_config.rxMs or bfd_interface_config.intervalMs}ms;''')
        if bfd_interface_config.txMs or bfd_interface_config.intervalMs:
            text_parts.append(f'''min tx interval {bfd_interface_config.txMs or bfd_interface_config.intervalMs}ms;''')
        if bfd_interface_config.idleMs:
            text_parts.append(f'''idle tx interval {bfd_interface_config.idleMs}ms;''')
        if bfd_interface_config.multiplier:
            text_parts.append(f'''multiplier {bfd_interface_config.multiplier};''')

        text_parts.append('};')

        all_bfd_texts.append('\n'.join(text_parts))

    final_bfd_text = '\n'.join(all_bfd_texts)

    return simple_format(render_config(BIRD_CONFIG_TEMPLATE, {
        'CURRENT_TIME': current_time_text,
        'GIT_VERSION': get_git_version(),
        'LOCALNET_NO_IMPORT': localnet_no_import_variable_text,
        'LOCALNET_NO_EXPORT': localnet_no_export_variable_text,
        'ROUTER_ID': router_id_text,
        'BFD_PROTOCOL': final_bfd_text,
        'DIRECT_PROTOCOL': dnames_text,
        'OSPF_IMPORT_FILTER': import_filter_text,
        'OSPF_EXPORT_FILTER': export_filter_text,
        'OSPF_AREA_CONFIG': final_area_text,
    }))
