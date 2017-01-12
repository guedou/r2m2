# Copyright (C) 2017 Guillaume Valadon <guillaume@valadon.net>

# r2m2 unit tests

@test "Check if miasm2 is available" {
  # Attempt to load the miasm2 Python module
  run python -m miasm2.core.cpu
}

@test "Check if r2m2 is available" {
  # Look for r2m2 in the list of plugins
  result=$(rasm2 -L | grep r2m2)
  echo $result
  [ $? -eq 0 ]
  [[ $result == *"r2m2"* ]]
}

@test "Assemble & disassemble ADDIU" {
  # Assemble ADDIU
  asm=$(R2M2_ARCH=mips32l rasm2 -a r2m2 'ADDIU A0, A1, 2')
  # Disassemble ADDIU
  result=$(export R2M2_ARCH=mips32l; echo $asm |rasm2 -a r2m2 -d - || true)
  echo $result
  [ "$result" == "ADDIU      A0, A1, 0x2" ]
}

@test "Emulate JUMP" {
  # Assemble instructions
  R2M2_ARCH=mips32b rasm2 -a r2m2 -B 'J 0x4; NOP' > binary
  # Call r2
  result=$(R2M2_ARCH=mips32b r2 -a r2m2 -qc 'e asm.emu=true; pd 2' binary)
  echo $result
  [[ $result == *"pc=0x4"* ]]
}

@test "Emulate ADDIU" {
  # Assemble ADDIU
  R2M2_ARCH=mips32l rasm2 -a r2m2 -B 'ADDIU A0, A1, 2' > binary
  # Call r2 and set a value to A1
  result=$(R2M2_ARCH=mips32l r2 -a r2m2 -qc 'e asm.emu=true ; ae 0x40,a1,=; pd 1' binary)
  echo $result
  [[ $result == *"a0=0x42"* ]]
}

@test "Emulate LB" {
  # Assemble LB
  R2M2_ARCH=mips32b rasm2 -a r2m2 -B 'LB A0, 0x1(A1)' > binary
  # Call r2
  result=$(R2M2_ARCH=mips32b r2 -a r2m2 -qc 'e asm.emu=true ; pd 1' binary)
  echo $result
  [[ $result == *"a0=0xa4"* ]]
}
