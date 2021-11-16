# EVM Bytecode Disassembler


The disassembler parses evm bytecode from the command line or from a file. It does not matter whether the bytecode is prefixed with "0x".

## Usage 
Command line example.

```
python3 disassembler.py 6060604052600261FFFF
```

Alternatively, input a file.

```
python3 disassembler.py evm.bin
```

## TODO

- [ ] add support for different forks