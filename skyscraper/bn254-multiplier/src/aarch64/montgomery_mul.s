// GENERATED FILE, DO NOT EDIT!
// in("x0") a[0], in("x1") a[1], in("x2") a[2], in("x3") a[3],
// in("x4") b[0], in("x5") b[1], in("x6") b[2], in("x7") b[3],
// in("x8") table,
// lateout("x0") out[0], lateout("x1") out[1], lateout("x2") out[2], lateout("x3") out[3],
// lateout("x4") _, lateout("x5") _, lateout("x6") _, lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _, lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _, lateout("x15") _, lateout("x16") _, lateout("x17") _, lateout("x20") _, lateout("x21") _, lateout("x22") _
  mov x9, #0
  adds x10, x0, x2
  adcs x11, x1, x3
  csetm x12, hs
  adds x13, x4, x6
  adcs x14, x5, x7
  csetm x15, hs
  and x16, x13, x12
  and x17, x14, x12
  and x20, x10, x15
  and x21, x11, x15
  and x12, x12, x15
  lsr x12, x12, #63
  adds x15, x16, x20
  adcs x16, x17, x21
  adc x12, x12, x9
  mul x17, x0, x4
  umulh x20, x0, x4
  mul x21, x1, x4
  umulh x4, x1, x4
  adds x20, x21, x20
  cinc x4, x4, hs
  mul x21, x0, x5
  umulh x0, x0, x5
  mul x22, x1, x5
  umulh x1, x1, x5
  adds x0, x22, x0
  cinc x1, x1, hs
  adds x5, x20, x21
  adcs x0, x4, x0
  cinc x1, x1, hs
  mul x4, x2, x6
  umulh x20, x2, x6
  mul x21, x3, x6
  umulh x6, x3, x6
  adds x20, x21, x20
  cinc x6, x6, hs
  mul x21, x2, x7
  umulh x2, x2, x7
  mul x22, x3, x7
  umulh x3, x3, x7
  adds x2, x22, x2
  cinc x3, x3, hs
  adds x7, x20, x21
  adcs x2, x6, x2
  cinc x3, x3, hs
  mul x6, x10, x13
  umulh x20, x10, x13
  mul x21, x11, x13
  umulh x13, x11, x13
  adds x20, x21, x20
  cinc x13, x13, hs
  mul x21, x10, x14
  umulh x10, x10, x14
  mul x22, x11, x14
  umulh x11, x11, x14
  adds x10, x22, x10
  cinc x11, x11, hs
  adds x14, x20, x21
  adcs x10, x13, x10
  cinc x11, x11, hs
  adds x10, x10, x15
  adcs x11, x11, x16
  adc x12, x12, x9
  subs x6, x6, x17
  sbcs x13, x14, x5
  sbcs x10, x10, x0
  sbcs x11, x11, x1
  sbcs x12, x12, x9
  subs x6, x6, x4
  sbcs x13, x13, x7
  sbcs x10, x10, x2
  sbcs x11, x11, x3
  sbcs x12, x12, x9
  adds x0, x0, x6
  adcs x1, x1, x13
  adcs x4, x4, x10
  adcs x6, x7, x11
  adcs x2, x2, x12
  adc x3, x3, x9
  ldp x7, x9, [x8, #0]
  mul x10, x17, x7
  umulh x7, x17, x7
  mul x11, x17, x9
  umulh x9, x17, x9
  ldp x12, x13, [x8, #16]
  mul x14, x17, x12
  umulh x12, x17, x12
  mul x15, x17, x13
  umulh x13, x17, x13
  adds x7, x11, x7
  adcs x9, x14, x9
  adcs x11, x15, x12
  cinc x12, x13, hs
  adds x1, x1, x10
  adcs x4, x4, x7
  adcs x6, x6, x9
  adcs x2, x2, x11
  adc x3, x3, x12
  ldp x7, x9, [x8, #32]
  mul x10, x5, x7
  umulh x7, x5, x7
  mul x11, x5, x9
  umulh x9, x5, x9
  ldp x12, x13, [x8, #48]
  mul x14, x5, x12
  umulh x12, x5, x12
  mul x15, x5, x13
  umulh x5, x5, x13
  adds x7, x11, x7
  adcs x9, x14, x9
  adcs x11, x15, x12
  cinc x5, x5, hs
  ldp x12, x13, [x8, #64]
  mul x14, x0, x12
  umulh x12, x0, x12
  mul x15, x0, x13
  umulh x13, x0, x13
  ldp x16, x17, [x8, #80]
  mul x20, x0, x16
  umulh x16, x0, x16
  mul x21, x0, x17
  umulh x0, x0, x17
  adds x12, x15, x12
  adcs x13, x20, x13
  adcs x15, x21, x16
  cinc x0, x0, hs
  adds x10, x10, x14
  adcs x7, x7, x12
  adcs x9, x9, x13
  adcs x11, x11, x15
  adc x0, x5, x0
  adds x1, x1, x10
  adcs x4, x4, x7
  adcs x5, x6, x9
  adcs x2, x2, x11
  adc x0, x3, x0
  ldr x3, [x8, #128]
  mul x3, x3, x1
  ldp x6, x7, [x8, #96]
  ldp x8, x9, [x8, #112]
  umulh x6, x3, x6
  mul x10, x3, x7
  umulh x7, x3, x7
  mul x11, x3, x8
  umulh x8, x3, x8
  mul x12, x3, x9
  umulh x3, x3, x9
  cmp x1, #1
  adcs x1, x4, x10
  adcs x4, x5, x11
  adcs x2, x2, x12
  cinc x5, x0, hs
  adds x0, x1, x6
  adcs x1, x4, x7
  adcs x2, x2, x8
  adc x3, x5, x3
