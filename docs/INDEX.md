# Documentation

Start with [Why Kapsel exists](../README.md#why-kapsel-exists) for the technical vision, the
[technical tour](TOUR.md) to follow the mechanism, or the [evaluation guide](EVALUATOR.md) to run
the published beta. The vision explains the direction; exact contracts remain the authority for
behavior.

## Learn

| Goal                              | Read                            |
| --------------------------------- | ------------------------------- |
| Understand Kapsel in five minutes | [README](../README.md)          |
| Follow one operation end to end   | [Technical tour](TOUR.md)       |
| Understand the product boundary   | [Technical scope](SCOPE.md)     |
| See how the code is composed      | [Architecture](ARCHITECTURE.md) |

## Use the published beta

| Goal                                  | Read                              |
| ------------------------------------- | --------------------------------- |
| Authenticate and run the artifact     | [Evaluation guide](EVALUATOR.md)  |
| Use the local CLI                     | [Evaluator commands](COMMANDS.md) |
| Use the fixed stdio MCP tool          | [MCP adapter](MCP.md)             |
| Verify release artifacts              | [Release contract](RELEASE.md)    |
| Upgrade or roll back a v0.1.1 journal | [Upgrade guide](UPGRADE.md)       |

## Exact reference

| Question                                                     | Owner                                                     |
| ------------------------------------------------------------ | --------------------------------------------------------- |
| What is in scope now?                                        | [Technical scope](SCOPE.md)                               |
| What do authorization, recovery, results, and receipts mean? | [Effect-gateway contract](EFFECT_GATEWAY.md)              |
| What does v0.2.0 promise?                                    | [v0.2.0 release contract](V0.2.md)                        |
| What threats and disclosures remain?                         | [Threat model](THREAT_MODEL.md) and [privacy](PRIVACY.md) |
| How do I report a vulnerability?                             | [Security policy](../SECURITY.md)                         |

## Contribute

| Goal                           | Read                                      |
| ------------------------------ | ----------------------------------------- |
| Contribute code or docs        | [Contributing](../CONTRIBUTING.md)        |
| Build or choose a focused gate | [Build and test](BUILD.md)                |
| Understand the proof strategy  | [Testing](TESTING.md)                     |
| Understand why a design exists | [Accepted decisions](decisions/README.md) |

## Unpublished work

Repository HEAD contains an unpublished customer-resident service and partial installer. Neither is
part of v0.2.0 or a supported installation path.

- [Kapsel service contract](KAPSEL_SERVICE.md)
- [Planned service operator journey](KAPSEL_SERVICE_OPERATOR.md)
- [Reconnectable agent action experiment](RECONNECTABLE_AGENT_ACTION.md)

## Authority order

When documents disagree:

1. [Technical scope](SCOPE.md) and the [effect-gateway contract](EFFECT_GATEWAY.md);
2. the direct contract for that surface;
3. conforming implementation and tests; then
4. accepted decisions, which explain why but do not override current contracts.
