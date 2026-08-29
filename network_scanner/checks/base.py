from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    name: str
    severity: str
    target: str
    evidence: str = ''
    recommendation: str = 'Verify manually and harden the exposed service.'

    def as_dict(self):
        return {
            'name': self.name,
            'severity': self.severity,
            'target': self.target,
            'evidence': str(self.evidence)[:240],
            'recommendation': self.recommendation,
        }


class Check:
    name = 'Unnamed Check'
    ports = ()
    severity = 'info'
    intrusive = False
    recommendation = 'Verify manually and harden the exposed service.'

    def applies_to(self, port, service, allow_intrusive=False):
        if self.intrusive and not allow_intrusive:
            return False
        return port in self.ports

    def run(self, host, port, service):
        raise NotImplementedError

    def finding(self, host, port, evidence=''):
        return Finding(
            self.name,
            self.severity,
            f'{host}:{port}',
            evidence,
            self.recommendation,
        ).as_dict()
