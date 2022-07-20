import json
from x86_64 import *

def to_hex_string(integer):
  return '{:02X}'.format(integer);

def to_op_string(ops, value):
  return '#' + str(ops.index(value))

if __name__ == "__main__":
  instructions = read_instruction_set('x86_64.xml');

  jsonInstructions = {};

  for instruction in instructions:
    has_vex_prefix = False # right we don't support this encoding so filter these instructions out
    has_evex_prefix = False
    jsonInstruction = {};
    jsonInstruction['summary'] = instruction.summary;

    jsonForms = [];
    for form in instruction.forms:
      jsonForm = {};
      jsonForm['operands'] = [];
      for operand in form.operands:
        jsonForm['operands'].append({
          'type': operand.type,
          'input': operand.is_input,
          'output': operand.is_output
        });

      jsonEncodings = [];
      for encoding in form.encodings:
        jsonEncoding = {};
        for comp in encoding.components:
          name = comp.__class__.__name__
          if name == 'Prefix':
            jsonEncoding['use_prefix'] = comp.is_mandatory
            jsonEncoding['prefix'] = to_hex_string(comp.byte)

          if name == 'VEX':
            has_vex_prefix = True

          if name == 'EVEX':
            has_evex_prefix = True

          if name == 'REX':
            # comp.set_ignored(comp.W, comp.R, comp.X, comp.B)
            # if comp.R.__class__ == Operand:
            #   comp.R = to_op_string(form.operands, comp.R)
            # if comp.X.__class__ == Operand:
            #   comp.X = to_op_string(form.operands, comp.X)
            # if comp.B.__class__ == Operand:
            #   comp.B = to_op_string(form.operands, comp.B)

            jsonEncoding['use_rex_prefix'] = comp.is_mandatory
            jsonEncoding['use_rex_w'] = bool(comp.W)
              
            # if comp.R is None: del jsonEncoding[name]['R']
            # if comp.W is None: del jsonEncoding[name]['W']
            # if comp.X is None: del jsonEncoding[name]['X']
            # if comp.B is None: del jsonEncoding[name]['B']

          if name == 'Opcode':
            if 'primary_opcode' in jsonEncoding:
              jsonEncoding['secondary_opcode'] = to_hex_string(comp.byte)
            else:
              if comp.byte == 0x0F:
                jsonEncoding['use_0f_prefix'] = True
              else:
                jsonEncoding['primary_opcode'] = to_hex_string(comp.byte)
                if comp.addend is not None:
                  jsonEncoding['use_opcode_addend'] = True
                  jsonEncoding['opcode_addend'] = to_op_string(form.operands, comp.addend)

          if name == 'ModRM':
            jsonEncoding['modrm_mod_direct'] = comp.mode == 0b11
            if isinstance(comp.reg, int):
              jsonEncoding['modrm_reg'] = str(comp.reg)
            else:
              jsonEncoding['modrm_reg'] = to_op_string(form.operands, comp.reg)
            jsonEncoding['modrm_rm'] = to_op_string(form.operands, comp.rm)

          # NOTE: imm, rel, moffs are really just encoded as immediates under different names
          # Don't quote me on that
          if name == 'Immediate' or name == 'CodeOffset' or name == 'DataOffset':
            jsonEncoding['imm_size'] = str(comp.size)
            jsonEncoding['imm_op'] = to_op_string(form.operands, comp.value)

          # TODO: when adding VEX prefix we need this
          # if name == 'RegisterByte'
          
            
        jsonEncodings.append(jsonEncoding);

      jsonForm['encodings'] = jsonEncodings;
      jsonForms.append(jsonForm);

    # Filter out unsupported VEX
    # TODO: we might want these later
    if not has_vex_prefix and not has_evex_prefix:
      jsonInstruction['forms'] = jsonForms;
      jsonInstructions[instruction.name] = jsonInstruction;
  
  jsonData = {
    "instruction_set": "x86-64", 
    "instructions": jsonInstructions
  }

  with open('x86_64.json', 'w') as outfile:
    json.dump(jsonData, outfile, indent=2)

# struct X64_Encoding {
#     bool use_prefix;
#     bool use_0f_prefix;
#     bool use_rex;
#     bool use_rex_w;
#     bool use_opcode_addend;
#    
#     u8 prefix;
#    
#     u8 primary_opcode;
#     u8 secondary_opcode;
#    
#     u8 modrm_mod;
#     u8 modrm_reg;
#     u8 modrm_rm;
#    
#     u8 imm_size;
#     u8 imm_op;
#    
#     bool is_valid;
# }


