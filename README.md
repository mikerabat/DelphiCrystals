# CRYSTALS Kyber & Dilithium for Delphi / Pascal

This project provides a Delphi/Object Pascal port of the official **CRYSTALS-Kyber** and **CRYSTALS-Dilithium** reference implementations from the PQ-CRYSTALS C projects.

The code is designed to stay structurally close to the original C sources, making it easy to compare, test and validate against the official implementations.

The project can be used with Delphi and Free Pascal Compiler (FPC), including on Windows and Linux platforms.

## Included Algorithms

### CRYSTALS-Kyber

**Kyber** is a post-quantum key encapsulation mechanism.

Supported parameter sets:

* `Kyber512`
* `Kyber768`
* `Kyber1024`

Typical operations:

* Generate key pair
* Encapsulate shared secret
* Decapsulate shared secret

### CRYSTALS-Dilithium

**Dilithium** is a post-quantum digital signature scheme.

Supported parameter sets:

* `Dilithium2`
* `Dilithium3`
* `Dilithium5`

Typical operations:

* Generate key pair
* Sign messages
* Verify signatures

## Project Structure

```text
├── src.
	├── kyber.pas
	├── dilithium.pas
	├── fips202.pas
	├── cryptRnd.pas
├── test
	├── kyber_test.dpr
	├── dilithiumtests.pas
	├── kybertests.pas
	├── FPCDilithiumTest.ppr (Codetyphon FPC project)
	├── FPCKyberTest.ppr (Codetyphon FPC project)
	└── dilithium_test.dpr
```

## Usage

Include the units directly in your Delphi or FPC project:

```pascal
uses
  kyber,
  dilithium,
  fips202;
```

Example usage is available in the included test projects.

## Notes

This is a direct port of the official reference implementations and is intended for testing, research, interoperability checks and integration experiments.

Before using it in production or security-critical environments, additional review and validation are strongly recommended.

## License

The original implementations are from the official PQ-CRYSTALS projects:

* https://github.com/pq-crystals/kyber
* https://github.com/pq-crystals/dilithium
