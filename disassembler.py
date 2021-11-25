import sys
import os
from binascii import unhexlify
from cbor2 import loads

def main():
	"""
	Accepts a file path or bytecode and prints disassembled info to console.
	"""
	if (len(sys.argv) != 2):
		print("Usage: python3 disassembler.py [bytecode]")
		return
	else:
		input: str = sys.argv[1]
		try:
			with open(os.path.abspath(input), 'r') as file:
				input = file.read().strip()
		except FileNotFoundError:
			pass
		if input.startswith("0x"):
			input = input[2:]
		print(input)
		bytecode: bytes = unhexlify(input)
		print(bytecode)
		bytecode = remove_metadata(bytecode) if (bytecode.find(b'\xa2\x64') != -1) else bytecode
		pc = 0	
		disassemble(pc, bytecode, len(bytecode))


def disassemble(pc: int, code: bytes, length: int):
	"""
	Steps through the program and translates it to the instruction.
	
	:param pc: the program counter
	:param code: the evm bytecode
	:param length: the length of the evm bytecode
	"""
	store = code
	code  = iter(code)
	while pc < length:
		opcode: bytes = next(code)
		assert isinstance(opcode, int)
		pc += 1
		name, operand_size = instruction_table[opcode]
		if operand_size:
			operand: int = 0
			# 1 byte = 8 bits = 2 hex digits
			for _ in range(operand_size):
				operand <<= 8 # shift 8 bits left 
				try:
					n = next(code) # grab next byte to create space
				except StopIteration:
					print(store[-2*operand_size:])
					break
				operand |= n # copy it's value into the "empty" space
			pc += operand_size
			print(pc, name, hex(operand))
		else:
			print(length, pc, name)

def remove_metadata(bytecode: bytes) -> bytes:
	print(bytecode)
	length_data = bytecode[-2:]
	# convert hex from base 16 to 10, add 2 bytes to account for '\xa2\x64' signifier
	metadata_length = int.from_bytes(length_data, "big") + 2 
	metadata = loads(bytecode[-metadata_length:])
	return bytecode[:-metadata_length]
	
instruction_table: dict[str, int] = {
	#opcode : (MNEMONIC, OPERAND_SIZE)
	0x0: ("STOP", 0),       
	0x1: ("ADD", 0),        
	0x2: ("MUL", 0),        
	0x3: ("SUB", 0),        
	0x4: ("DIV", 0),        
	0x5: ("SDIV", 0),       
	0x6: ("MOD", 0),        
	0x7: ("SMOD", 0),       
	0x8: ("ADDMOD", 0), 
	0x9: ("MULMOD", 0), 
	0xA: ("EXP", 0),        
	0xB: ("SIGNEXTEND", 0), 
	0x10: ("LT", 0),         
	0x11: ("GT", 0),         
	0x12: ("SLT", 0),        
	0x13: ("SGT", 0),        
	0x14: ("EQ", 0),         
	0x15: ("ISZERO", 0),     
	0x16: ("AND", 0),    
	0x17: ("OR", 0),     
	0x18: ("XOR", 0),    
	0x19: ("NOT", 0),        
	0x1A: ("BYTE", 0),   
	0x1B: ("SHL", 0), 
	0x1C: ("SHR", 0), 
	0x1D: ("SAR", 0), 
	0x20: ("SHA3", 0), 
	0x30: ("ADDRESS", 0),      
	0x31: ("BALANCE", 0),      
	0x32: ("ORIGIN", 0),       
	0x33: ("CALLER", 0),       
	0x34: ("CALLVALUE", 0),    
	0x35: ("CALLDATALOAD", 0), 
	0x36: ("CALLDATASIZE", 0), 
	0x37: ("CALLDATACOPY", 0), 
	0x38: ("CODESIZE", 0),     
	0x39: ("CODECOPY", 0),     
	0x3A: ("GASPRICE", 0),     
	0x3B: ("EXTCODESIZE", 0), 
	0x3C: ("EXTCODECOPY", 0), 
	0x3D: ("RETURNDATASIZE", 0), 
	0x3E: ("RETURNDATACOPY", 0), 
	0x3F: ("EXTCODEHASH", 0), 
	0x40: ("BLOCKHASH", 0),   
	0x41: ("COINBASE", 0),    
	0x42: ("TIMESTAMP", 0),   
	0x43: ("NUMBER", 0),      
	0x44: ("DIFFICULTY", 0),  
	0x45: ("GASLIMIT", 0),    
	0x46: ("CHAINID", 0), 
	0x47: ("SELFBALANCE", 0), 
	0x48: ("BASEFEE", 0), 
	0x50: ("POP", 0), 
	0x51: ("MLOAD", 0),    
	0x52: ("MSTORE", 0),   
	0x53: ("MSTORE8", 0),  
	0x54: ("SLOAD", 0),    
	0x55: ("SSTORE", 0),   
	0x56: ("JUMP", 0),     
	0x57: ("JUMPI", 0),    
	0x58: ("PC", 0),       
	0x59: ("MSIZE", 0),    
	0x5A: ("GAS", 0),      
	0x5B: ("JUMPDEST", 0), 
	0x60: ("PUSH1", 1),  
	0x61: ("PUSH2", 2),  
	0x62: ("PUSH3", 3),  
	0x63: ("PUSH4", 4),  
	0x64: ("PUSH5", 5),  
	0x65: ("PUSH6", 6),  
	0x66: ("PUSH7", 7),  
	0x67: ("PUSH8", 8),  
	0x68: ("PUSH9", 9),  
	0x69: ("PUSH10", 10), 
	0x6A: ("PUSH11", 11), 
	0x6B: ("PUSH12", 12), 
	0x6C: ("PUSH13", 13), 
	0x6D: ("PUSH14", 14), 
	0x6E: ("PUSH15", 15), 
	0x6F: ("PUSH16", 16), 
	0x70: ("PUSH17", 17), 
	0x71: ("PUSH18", 18), 
	0x72: ("PUSH19", 19), 
	0x73: ("PUSH20", 20), 
	0x74: ("PUSH21", 21), 
	0x75: ("PUSH22", 22), 
	0x76: ("PUSH23", 23), 
	0x77: ("PUSH24", 24), 
	0x78: ("PUSH25", 25), 
	0x79: ("PUSH26", 26), 
	0x7A: ("PUSH27", 27), 
	0x7B: ("PUSH28", 28), 
	0x7C: ("PUSH29", 29), 
	0x7D: ("PUSH30", 30), 
	0x7E: ("PUSH31", 31), 
	0x7F: ("PUSH32", 32), 
	0x80: ("DUP1", 0),  
	0x81: ("DUP2", 0),  
	0x82: ("DUP3", 0),  
	0x83: ("DUP4", 0),  
	0x84: ("DUP5", 0),  
	0x85: ("DUP6", 0),  
	0x86: ("DUP7", 0),  
	0x87: ("DUP8", 0),  
	0x88: ("DUP9", 0),  
	0x89: ("DUP10", 0),	
	0x8A: ("DUP11", 0),	
	0x8B: ("DUP12", 0),
	0x8C: ("DUP13", 0),
	0x8D: ("DUP14", 0),
	0x8E: ("DUP15", 0),
	0x8F: ("DUP16", 0),
	0x90: ("SWAP1", 0),  
	0x91: ("SWAP2", 0),  
	0x92: ("SWAP3", 0),  
	0x93: ("SWAP4", 0),  
	0x94: ("SWAP5", 0),  
	0x95: ("SWAP6", 0),  
	0x96: ("SWAP7", 0),  
	0x97: ("SWAP8", 0),  
	0x98: ("SWAP9",  0),
	0x99: ("SWAP10", 0),
	0x9A: ("SWAP11", 0),
	0x9B: ("SWAP12", 0),
	0x9C: ("SWAP13", 0),
	0x9D: ("SWAP14", 0),
	0x9E: ("SWAP15", 0),
	0x9F: ("SWAP16", 0),
	0xA0: ("LOG0", 0),   
	0xA1: ("LOG1", 0),   
	0xA2: ("LOG2", 0),   
	0xA3: ("LOG3", 0),   
	0xA4: ("LOG4", 0),   
	0xF0: ("CREATE", 0),       
	0xF1: ("CALL", 0),         
	0xF2: ("CALLCODE", 0),     
	0xF3: ("RETURN", 0),       
	0xF4: ("DELEGATECALL", 0), 
	0xF5: ("CREATE2", 0), 
	0xFA: ("STATICCALL", 0), 
	0xFD: ("REVERT", 0),       
	0xFE: ("INVALID", 0),      
	0xFF: ("SELFDESTRUCT", 0)
}

if __name__ == "__main__":
	main()
