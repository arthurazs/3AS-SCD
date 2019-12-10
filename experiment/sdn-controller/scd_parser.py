import xml.etree.ElementTree as ET


def parse_scd(path):
    def find(node, value):
        return node.find('{http://www.iec.ch/61850/2003/SCL}' + value)

    def findall(node, value):
        return node.findall('{http://www.iec.ch/61850/2003/SCL}' + value)

    def format_mac(value):
        return value.lower().replace('-', ':')

    tree = ET.parse(path)
    root = tree.getroot()

    communication = find(root, 'Communication')
    aps = findall(communication[0], 'ConnectedAP')

    substation = {}

    for ap in aps:
        ied_name = ap.get('iedName')
        address = find(ap, 'Address')
        privates = findall(address, 'P')
        for p in privates:
            if p.get('type') == 'IP':
                ip = p.text
            break

        gses = findall(ap, 'GSE')
        publish_goose = []
        for gse in gses:
            address = find(gse, 'Address')
            privates = findall(address, 'P')
            for p in privates:
                if p.get('type') == 'MAC-Address':
                    publish_goose.append(format_mac(p.text))
                    break

        smvs = findall(ap, 'SMV')
        publish_sv = []
        for smv in smvs:
            address = find(smv, 'Address')
            privates = findall(address, 'P')
            for p in privates:
                if p.get('type') == 'MAC-Address':
                    publish_sv.append(format_mac(p.text))
                    break

        substation[ied_name] = {
            'ip': ip,
            'publish': {'goose': publish_goose, 'sv': publish_sv}}

    ieds = findall(root, 'IED')
    for ied in ieds:
        ied_name = ied.get('name')
        privates = findall(ied, 'Private')

        subscribe_goose = []
        subscribe_sv = []
        for private in privates:
            if private.get('type') == 'SEL_GooseSubscription':
                subscribe_goose.append(format_mac(private[0].get('mAddr')))
            if private.get('type') == 'SEL_SVSubscription':
                subscribe_sv.append(format_mac(private[0].get('mAddr')))
        substation[ied_name]['subscribe'] = {
            'goose': subscribe_goose,
            'sv': subscribe_sv,
        }
    return substation
