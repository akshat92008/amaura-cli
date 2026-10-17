# Known Limitations

No software can guarantee perfect correctness across arbitrary tasks. Amaura discloses its current limitations:

1. **Local-Only Scope**: In v0.1, checks are bounded to local unit/integration tests, syntax builds, and AST static analysis.
2. **Dynamic Concurrency**: High-concurrency race conditions and remote network timeouts are not exhaustively simulated.
3. **Semantic Novelty**: Amaura can verify whether code compiles and passes tests, but cannot certify subjective properties such as scientific novelty or architectural elegance without human review.
4. **Adversarial Obfuscation**: Highly sophisticated, intentional malware that mimics benign unit tests may evade AST pattern matching without deep dynamic sandboxing.
