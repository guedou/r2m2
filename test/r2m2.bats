# Copyright (C) 2018 Guillaume Valadon <guillaume@valadon.net>

# r2m2 unit tests

@test "Check if miasm2 is available" {
  # Attempt to load the miasm2 Python module
  run python2 -m miasm2.core.cpu
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

@test "Emulate CALL" {
  # Assemble CALL
  rasm2 -B 'CALL 0x337c' > binary
  # Call r2
  result=$(R2M2_ARCH=x86_64 r2 -a r2m2 -qc 'e asm.emu=true ; pd 1' binary)
  echo $result
  [[ $result == *"rip=0x337c"* ]]
}

@test "Emulate JZ" {
  # Assemble JZ
  rasm2 -B 'JZ 0x28' > binary
  # Call r2
  result=$(R2M2_ARCH=x86_64 r2 -a r2m2 -m 0x1000 -qc 'e asm.esil=true; pd 1' binary)
  echo $result
  [[ $result == *"zf,?{"* ]]
}

@test "Emulate JMP with an offset" {
  # Assemble JMP
  rasm2 -B 'JMP 0x28' > binary
  # Call r2
  result=$(R2M2_ARCH=x86_64 r2 -a r2m2 -m 0x100000000 -qc 'pd 1' binary)
  echo $result
  [[ $result == *",=<"* ]]
  [[ $result == *"0x100000028"* ]]
}

@test "ExpSlice in condition" {
  # Build the binary
  echo -ne "\x75\xdc\x81\x05" > binary
  # Call r2
  result=$(R2M2_ARCH=mips32l r2 -a r2m2 -e scr.color=0 -e asm.emu=true -qc 'pd 1' binary 2>&1)
  echo $result
  [[ $result != *"ExprSlice"* ]]
}

@test "Emulate SHL" {
  # Create the binary from raw bytes
  echo -ne "\x49\xd3\xe7" > binary
  # Call r2
  result=$(R2M2_ARCH=x86_64 r2 -a r2m2 -qc 'e asm.emu=true; ae 1,r15,=,2,cl,=; pd 1' binary)
  echo $result
  [[ $result == *"r15=0x4"* ]]
}

@test "Emulate JMP with an address" {
  # Create the binary from raw bytes
  echo -ne '\xff\x24\x25\x03\x00\x00\x00\x00' > binary
  # Call r2
  result=$(R2M2_ARCH=x86_64 r2 -a r2m2 -qc 'e asm.emu=true; pd 1' binary 2>&1)
  echo $result
  [[ $result != *"miasm_anal()"* ]]
} 

@test "Assemble & disassemble JZ with offsets" {
  export R2M2_ARCH=x86_32

  # Assemble JZ without and with an offset
  result_1=$(rasm2 -a r2m2 "JZ 0xA")
  echo $result_1
  result_2=$(rasm2 -a r2m2 -o 0x1000 "JZ 0x100A")
  echo $result_2
  [ "$result_1" == "7408" ]
  [ "$result_1" == "$result_2" ]

  # Disassemble with an offset
  result=$(echo $result_1 |rasm2 -a r2m2 -d -o 0x2800 -; echo)
  echo $result
  [ "$result" == "JZ         0x280A" ]

  # Call r2
  result=$(r2 -a r2m2 -e asm.emu=true -m 0x2800 -qc 'pd 1' binary)
  [[ $result != *"JMP        0x280A"* ]]
}

@test "Check offset computation in call" {
  export R2M2_ARCH=armb

  # Assemble an ARM call
  rasm2 -a r2m2 -B "BL 0x8" > binary

  # Call r2
  result=$(r2 -a r2m2 -m 0x2800 -qc 'af+ 0x2808 function_ut; pd 1' -e asm.emu=true binary)
  [[ $result == *"function_ut"* ]]
  [[ $result == *"pc=0x2808"* ]]
}

@test "Check calling convention" {
  export PATH=radare2/shlr/sdb/:$PATH
  if ! which sdb > /dev/null
  then
    skip "sdb command not found"
  fi

  export R2M2_ARCH=armb

  # Compile and test the SDB
  cat test/r2m2-cc.txt |sdb r2m2-cc.sdb -
  result=$(sdb r2m2-cc.sdb cc.r2m2.name)
  [[ $result == *"r2m2"* ]]

  # Call r2
  result=$(r2 -a r2m2 -qc 'af+ 0x20 strlen; e io.cache=true; s 0; wz Hello; s 8 ; wa MOV R1,0; s 12; wa BL 0x20 ; e asm.emu=true ; pd 2 @ 8' -)
  echo $result
  [[ $result == *"strlen"* ]]
  [[ $result == *'"Hello"'* ]]
}
