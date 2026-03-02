# Threat Model and Launch Checklist

## Threats
- partitioning and eclipse attempts
- malformed/DoS traffic
- seed outages
- validator equivocation
- operational misconfiguration during launch

## Checklist
- [ ] full test suite green (`ctest`)
- [ ] sanitizer + fuzz sanity run completed
- [ ] genesis reproducibility independently confirmed
- [ ] multi-region seed redundancy ready
- [ ] >= minimum validator count online
- [ ] >= minimum public lightservers online
- [ ] observer divergence monitoring active
- [ ] incident response runbook published
