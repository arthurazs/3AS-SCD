from uuid import uuid4
from vakt import ALLOW_ACCESS, DENY_ACCESS
from vakt import Policy, MemoryStorage, Guard, RulesChecker, Inquiry
from vakt.rules import Eq, Any, StartsWith, Not, Or
from scd_parser import parse_scd


class AccessControl:

    def add_policy(self, ied, action, protocol,
                   address=None, access=ALLOW_ACCESS):
        if type(ied) is not list:
            ied = [ied]
        if type(action) is not list:
            action = [action]
        if type(protocol) is not list:
            protocol = [protocol]
        if address:
            self._storage.add(Policy(
                str(uuid4()), subjects=ied, actions=action,
                context=address, resources=protocol, effect=access))
        else:
            self._storage.add(Policy(
                str(uuid4()), subjects=ied, actions=action,
                resources=protocol, effect=access))

    def _find_and_add_policy(self, data, name, action, protocol):
        protocol_set = ()
        for value in data[action][protocol]:
            protocol_set += (Eq(value),)
        protocol_set = set(protocol_set)
        if protocol_set:
            self.add_policy(
                ied=Eq(name), action=Eq(action),
                address={'mac': Or(*protocol_set)},
                protocol=Eq(protocol.upper())
            )

    def _from_file(self, path):

        for ied, value in parse_scd(path).items():
            self.add_policy(
                ied=Eq(ied), action=Any(),
                address={'ip': Eq(value['ip'])},
                protocol=Eq('MMS'))

            self._find_and_add_policy(value, ied, 'publish', 'goose')
            self._find_and_add_policy(value, ied, 'publish', 'sv')
            self._find_and_add_policy(value, ied, 'subscribe', 'goose')
            self._find_and_add_policy(value, ied, 'subscribe', 'sv')

    def __init__(self, auto=None):
        self._storage = MemoryStorage()

        if auto:
            self._from_file(auto)

        self.add_policy(
            ied=Any(),
            action=[Eq('publish'), Eq('subscribe')],
            address={'mac': Not(StartsWith('01:0c:cd:01'))},
            protocol=Eq('GOOSE'),
            access=DENY_ACCESS)

        self.add_policy(
            ied=Any(),
            action=[Eq('publish'), Eq('subscribe')],
            address={'mac': Not(StartsWith('01:0c:cd:04'))},
            protocol=Eq('SV'),
            access=DENY_ACCESS)

        self._guard = Guard(self._storage, RulesChecker())

    def is_allowed(self, ied, action, address, protocol):
        return self._guard.is_allowed(Inquiry(
            subject=ied, action=action, context=address, resource=protocol))
