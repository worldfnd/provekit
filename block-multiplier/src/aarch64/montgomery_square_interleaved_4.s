// GENERATED FILE, DO NOT EDIT!
// in("x0") a[0], in("x1") a[1], in("x2") a[2], in("x3") a[3],
// in("x4") a1[0], in("x5") a1[1], in("x6") a1[2], in("x7") a1[3],
// in("v0") av[0], in("v1") av[1], in("v2") av[2], in("v3") av[3],
// lateout("x0") out[0], lateout("x1") out[1], lateout("x2") out[2], lateout("x3") out[3],
// lateout("x4") out1[0], lateout("x5") out1[1], lateout("x6") out1[2], lateout("x7") out1[3],
// lateout("v0") outv[0], lateout("v1") outv[1], lateout("v2") outv[2], lateout("v3") outv[3],
// lateout("x8") _, lateout("x9") _, lateout("x10") _, lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _, lateout("x15") _, lateout("x16") _, lateout("x17") _, lateout("x20") _, lateout("x21") _, lateout("x22") _, lateout("x23") _, lateout("x24") _, lateout("v4") _, lateout("v5") _, lateout("v6") _, lateout("v7") _, lateout("v8") _, lateout("v9") _, lateout("v10") _, lateout("v11") _, lateout("v12") _, lateout("v13") _, lateout("v14") _, lateout("v15") _, lateout("v16") _, lateout("v17") _, lateout("v18") _, lateout("v19") _,
// lateout("lr") _
  mov x8, #4503599627370495
  mul x9, x0, x0
  dup.2d v4, x8
  umulh x10, x0, x0
  mov x11, #5075556780046548992
  mul x12, x0, x1
  dup.2d v5, x11
  mov x11, #1
  umulh x13, x0, x1
  movk x11, #18032, lsl 48
  adds x10, x12, x10
  cinc x14, x13, hs
  dup.2d v6, x11
  mul x11, x0, x2
  shl.2d v7, v1, #14
  shl.2d v8, v2, #26
  umulh x15, x0, x2
  shl.2d v9, v3, #38
  adds x14, x11, x14
  cinc x16, x15, hs
  ushr.2d v3, v3, #14
  mul x17, x0, x3
  shl.2d v10, v0, #2
  umulh x0, x0, x3
  usra.2d v7, v0, #50
  usra.2d v8, v1, #38
  adds x16, x17, x16
  cinc x20, x0, hs
  usra.2d v9, v2, #26
  adds x10, x12, x10
  cinc x12, x13, hs
  and.16b v0, v10, v4
  mul x13, x1, x1
  and.16b v1, v7, v4
  and.16b v2, v8, v4
  umulh x21, x1, x1
  and.16b v7, v9, v4
  adds x12, x13, x12
  cinc x13, x21, hs
  mov x21, #13605374474286268416
  adds x12, x12, x14
  cinc x13, x13, hs
  dup.2d v8, x21
  mul x14, x1, x2
  mov x21, #6440147467139809280
  dup.2d v9, x21
  umulh x21, x1, x2
  mov x22, #3688448094816436224
  adds x13, x14, x13
  cinc x23, x21, hs
  dup.2d v10, x22
  adds x13, x13, x16
  cinc x16, x23, hs
  mov x22, #9209861237972664320
  dup.2d v11, x22
  mul x22, x1, x3
  mov x23, #12218265789056155648
  umulh x1, x1, x3
  dup.2d v12, x23
  adds x16, x22, x16
  cinc x23, x1, hs
  mov x24, #17739678932212383744
  adds x16, x16, x20
  cinc x20, x23, hs
  dup.2d v13, x24
  mov x23, #2301339409586323456
  adds x11, x11, x12
  cinc x12, x15, hs
  dup.2d v14, x23
  adds x12, x14, x12
  cinc x14, x21, hs
  mov x15, #7822752552742551552
  adds x12, x12, x13
  cinc x13, x14, hs
  dup.2d v15, x15
  mov x14, #5071053180419178496
  mul x15, x2, x2
  dup.2d v16, x14
  umulh x14, x2, x2
  mov x21, #16352570246982270976
  adds x13, x15, x13
  cinc x14, x14, hs
  dup.2d v17, x21
  adds x13, x13, x16
  cinc x14, x14, hs
  ucvtf.2d v0, v0
  ucvtf.2d v1, v1
  mul x15, x2, x3
  ucvtf.2d v2, v2
  umulh x2, x2, x3
  ucvtf.2d v7, v7
  adds x14, x15, x14
  cinc x16, x2, hs
  ucvtf.2d v3, v3
  mov.16b v18, v5
  adds x14, x14, x20
  cinc x16, x16, hs
  fmla.2d v18, v0, v0
  adds x12, x17, x12
  cinc x0, x0, hs
  fsub.2d v19, v6, v18
  adds x0, x22, x0
  cinc x1, x1, hs
  fmla.2d v19, v0, v0
  adds x0, x0, x13
  cinc x1, x1, hs
  add.2d v10, v10, v18
  add.2d v8, v8, v19
  adds x1, x15, x1
  cinc x2, x2, hs
  mov.16b v18, v5
  adds x1, x1, x14
  cinc x2, x2, hs
  fmla.2d v18, v0, v1
  mul x13, x3, x3
  fsub.2d v19, v6, v18
  fmla.2d v19, v0, v1
  umulh x3, x3, x3
  add.2d v18, v18, v18
  adds x2, x13, x2
  cinc x3, x3, hs
  add.2d v19, v19, v19
  adds x2, x2, x16
  cinc x3, x3, hs
  add.2d v12, v12, v18
  mov x13, #48718
  add.2d v10, v10, v19
  mov.16b v18, v5
  movk x13, #4732, lsl 16
  fmla.2d v18, v0, v2
  movk x13, #45078, lsl 32
  fsub.2d v19, v6, v18
  movk x13, #39852, lsl 48
  fmla.2d v19, v0, v2
  add.2d v18, v18, v18
  mov x14, #16676
  add.2d v19, v19, v19
  movk x14, #12692, lsl 16
  add.2d v14, v14, v18
  movk x14, #20986, lsl 32
  add.2d v12, v12, v19
  movk x14, #2848, lsl 48
  mov.16b v18, v5
  fmla.2d v18, v0, v7
  mov x15, #51052
  fsub.2d v19, v6, v18
  movk x15, #24721, lsl 16
  fmla.2d v19, v0, v7
  movk x15, #61092, lsl 32
  add.2d v18, v18, v18
  add.2d v19, v19, v19
  movk x15, #45156, lsl 48
  add.2d v16, v16, v18
  mov x16, #3197
  add.2d v14, v14, v19
  movk x16, #18936, lsl 16
  mov.16b v18, v5
  movk x16, #10922, lsl 32
  fmla.2d v18, v0, v3
  fsub.2d v19, v6, v18
  movk x16, #11014, lsl 48
  fmla.2d v19, v0, v3
  mul x17, x13, x9
  add.2d v0, v18, v18
  umulh x13, x13, x9
  add.2d v18, v19, v19
  add.2d v0, v17, v0
  adds x12, x17, x12
  cinc x13, x13, hs
  add.2d v16, v16, v18
  mul x17, x14, x9
  mov.16b v17, v5
  umulh x14, x14, x9
  fmla.2d v17, v1, v1
  adds x13, x17, x13
  cinc x14, x14, hs
  fsub.2d v18, v6, v17
  fmla.2d v18, v1, v1
  adds x0, x13, x0
  cinc x13, x14, hs
  add.2d v14, v14, v17
  mul x14, x15, x9
  add.2d v12, v12, v18
  umulh x15, x15, x9
  mov.16b v17, v5
  fmla.2d v17, v1, v2
  adds x13, x14, x13
  cinc x14, x15, hs
  fsub.2d v18, v6, v17
  adds x1, x13, x1
  cinc x13, x14, hs
  fmla.2d v18, v1, v2
  mul x14, x16, x9
  add.2d v17, v17, v17
  umulh x9, x16, x9
  add.2d v18, v18, v18
  add.2d v16, v16, v17
  adds x13, x14, x13
  cinc x9, x9, hs
  add.2d v14, v14, v18
  adds x2, x13, x2
  cinc x9, x9, hs
  mov.16b v17, v5
  add x3, x3, x9
  fmla.2d v17, v1, v7
  fsub.2d v18, v6, v17
  mov x9, #56431
  fmla.2d v18, v1, v7
  movk x9, #30457, lsl 16
  add.2d v17, v17, v17
  movk x9, #30012, lsl 32
  add.2d v18, v18, v18
  movk x9, #6382, lsl 48
  add.2d v0, v0, v17
  add.2d v16, v16, v18
  mov x13, #59151
  mov.16b v17, v5
  movk x13, #41769, lsl 16
  fmla.2d v17, v1, v3
  movk x13, #32276, lsl 32
  fsub.2d v18, v6, v17
  fmla.2d v18, v1, v3
  movk x13, #21677, lsl 48
  add.2d v1, v17, v17
  mov x14, #34015
  add.2d v17, v18, v18
  movk x14, #20342, lsl 16
  add.2d v1, v15, v1
  movk x14, #13935, lsl 32
  add.2d v0, v0, v17
  mov.16b v15, v5
  movk x14, #11030, lsl 48
  fmla.2d v15, v2, v2
  mov x15, #13689
  fsub.2d v17, v6, v15
  movk x15, #8159, lsl 16
  fmla.2d v17, v2, v2
  add.2d v0, v0, v15
  movk x15, #215, lsl 32
  add.2d v15, v16, v17
  movk x15, #4913, lsl 48
  mov.16b v16, v5
  mul x16, x9, x10
  fmla.2d v16, v2, v7
  umulh x9, x9, x10
  fsub.2d v17, v6, v16
  fmla.2d v17, v2, v7
  adds x12, x16, x12
  cinc x9, x9, hs
  add.2d v16, v16, v16
  mul x16, x13, x10
  add.2d v17, v17, v17
  umulh x13, x13, x10
  add.2d v1, v1, v16
  add.2d v0, v0, v17
  adds x9, x16, x9
  cinc x13, x13, hs
  mov.16b v16, v5
  adds x0, x9, x0
  cinc x9, x13, hs
  fmla.2d v16, v2, v3
  mul x13, x14, x10
  fsub.2d v17, v6, v16
  fmla.2d v17, v2, v3
  umulh x14, x14, x10
  add.2d v2, v16, v16
  adds x9, x13, x9
  cinc x13, x14, hs
  add.2d v16, v17, v17
  adds x1, x9, x1
  cinc x9, x13, hs
  add.2d v2, v13, v2
  mul x13, x15, x10
  add.2d v1, v1, v16
  mov.16b v13, v5
  umulh x10, x15, x10
  fmla.2d v13, v7, v7
  adds x9, x13, x9
  cinc x10, x10, hs
  fsub.2d v16, v6, v13
  adds x2, x9, x2
  cinc x9, x10, hs
  fmla.2d v16, v7, v7
  add.2d v2, v2, v13
  add x3, x3, x9
  add.2d v1, v1, v16
  mov x9, #61005
  mov.16b v13, v5
  movk x9, #58262, lsl 16
  fmla.2d v13, v7, v3
  movk x9, #32851, lsl 32
  fsub.2d v16, v6, v13
  fmla.2d v16, v7, v3
  movk x9, #11582, lsl 48
  add.2d v7, v13, v13
  mov x10, #37581
  add.2d v13, v16, v16
  movk x10, #43836, lsl 16
  add.2d v7, v11, v7
  add.2d v2, v2, v13
  movk x10, #36286, lsl 32
  mov.16b v11, v5
  movk x10, #51783, lsl 48
  fmla.2d v11, v3, v3
  mov x13, #10899
  fsub.2d v13, v6, v11
  movk x13, #30709, lsl 16
  fmla.2d v13, v3, v3
  add.2d v3, v9, v11
  movk x13, #61551, lsl 32
  add.2d v7, v7, v13
  movk x13, #45784, lsl 48
  usra.2d v10, v8, #52
  mov x14, #36612
  usra.2d v12, v10, #52
  usra.2d v14, v12, #52
  movk x14, #63402, lsl 16
  usra.2d v15, v14, #52
  movk x14, #47623, lsl 32
  and.16b v8, v8, v4
  movk x14, #9430, lsl 48
  and.16b v9, v10, v4
  mul x15, x9, x11
  and.16b v10, v12, v4
  and.16b v4, v14, v4
  umulh x9, x9, x11
  ucvtf.2d v8, v8
  adds x12, x15, x12
  cinc x9, x9, hs
  mov x15, #37864
  mul x16, x10, x11
  movk x15, #1815, lsl 16
  movk x15, #28960, lsl 32
  umulh x10, x10, x11
  movk x15, #17153, lsl 48
  adds x9, x16, x9
  cinc x10, x10, hs
  dup.2d v11, x15
  adds x0, x9, x0
  cinc x9, x10, hs
  mov.16b v12, v5
  mul x10, x13, x11
  fmla.2d v12, v8, v11
  fsub.2d v13, v6, v12
  umulh x13, x13, x11
  fmla.2d v13, v8, v11
  adds x9, x10, x9
  cinc x10, x13, hs
  add.2d v0, v0, v12
  adds x1, x9, x1
  cinc x9, x10, hs
  add.2d v11, v15, v13
  mov x10, #46128
  mul x13, x14, x11
  movk x10, #29964, lsl 16
  umulh x11, x14, x11
  movk x10, #7587, lsl 32
  adds x9, x13, x9
  cinc x11, x11, hs
  movk x10, #17161, lsl 48
  adds x2, x9, x2
  cinc x9, x11, hs
  dup.2d v12, x10
  mov.16b v13, v5
  add x3, x3, x9
  fmla.2d v13, v8, v12
  mov x9, #65535
  fsub.2d v14, v6, v13
  movk x9, #61439, lsl 16
  fmla.2d v14, v8, v12
  add.2d v1, v1, v13
  movk x9, #62867, lsl 32
  add.2d v0, v0, v14
  movk x9, #49889, lsl 48
  mov x10, #52826
  mul x9, x9, x12
  movk x10, #57790, lsl 16
  mov x11, #1
  movk x10, #55431, lsl 32
  movk x10, #17196, lsl 48
  movk x11, #61440, lsl 16
  dup.2d v12, x10
  movk x11, #62867, lsl 32
  mov.16b v13, v5
  movk x11, #17377, lsl 48
  fmla.2d v13, v8, v12
  fsub.2d v14, v6, v13
  mov x10, #28817
  fmla.2d v14, v8, v12
  movk x10, #31161, lsl 16
  add.2d v2, v2, v13
  movk x10, #59464, lsl 32
  add.2d v1, v1, v14
  movk x10, #10291, lsl 48
  mov x13, #31276
  movk x13, #21262, lsl 16
  mov x14, #22621
  movk x13, #2304, lsl 32
  movk x14, #33153, lsl 16
  movk x13, #17182, lsl 48
  movk x14, #17846, lsl 32
  dup.2d v12, x13
  mov.16b v13, v5
  movk x14, #47184, lsl 48
  fmla.2d v13, v8, v12
  mov x13, #41001
  fsub.2d v14, v6, v13
  movk x13, #57649, lsl 16
  fmla.2d v14, v8, v12
  movk x13, #20082, lsl 32
  add.2d v7, v7, v13
  add.2d v2, v2, v14
  movk x13, #12388, lsl 48
  mov x15, #28672
  mul x16, x11, x9
  movk x15, #24515, lsl 16
  umulh x11, x11, x9
  movk x15, #54929, lsl 32
  movk x15, #17064, lsl 48
  cmn x16, x12
  cinc x11, x11, hs
  dup.2d v12, x15
  mul x12, x10, x9
  mov.16b v13, v5
  umulh x10, x10, x9
  fmla.2d v13, v8, v12
  adds x11, x12, x11
  cinc x10, x10, hs
  fsub.2d v14, v6, v13
  fmla.2d v14, v8, v12
  adds x0, x11, x0
  cinc x10, x10, hs
  add.2d v3, v3, v13
  mul x11, x14, x9
  add.2d v7, v7, v14
  umulh x12, x14, x9
  ucvtf.2d v8, v9
  mov x14, #44768
  adds x10, x11, x10
  cinc x11, x12, hs
  movk x14, #51919, lsl 16
  adds x1, x10, x1
  cinc x10, x11, hs
  movk x14, #6346, lsl 32
  mul x11, x13, x9
  movk x14, #17133, lsl 48
  umulh x9, x13, x9
  dup.2d v9, x14
  mov.16b v12, v5
  adds x10, x11, x10
  cinc x9, x9, hs
  fmla.2d v12, v8, v9
  adds x2, x10, x2
  cinc x9, x9, hs
  fsub.2d v13, v6, v12
  add x3, x3, x9
  fmla.2d v13, v8, v9
  add.2d v0, v0, v12
  mov x9, #2
  add.2d v9, v11, v13
  movk x9, #57344, lsl 16
  mov x10, #47492
  movk x9, #60199, lsl 32
  movk x10, #23630, lsl 16
  movk x9, #34755, lsl 48
  movk x10, #49985, lsl 32
  movk x10, #17168, lsl 48
  mov x11, #57634
  dup.2d v11, x10
  movk x11, #62322, lsl 16
  mov.16b v12, v5
  movk x11, #53392, lsl 32
  fmla.2d v12, v8, v11
  fsub.2d v13, v6, v12
  movk x11, #20583, lsl 48
  fmla.2d v13, v8, v11
  mov x10, #45242
  add.2d v1, v1, v12
  movk x10, #770, lsl 16
  add.2d v0, v0, v13
  movk x10, #35693, lsl 32
  mov x12, #57936
  movk x12, #54828, lsl 16
  movk x10, #28832, lsl 48
  movk x12, #18292, lsl 32
  mov x13, #16467
  movk x12, #17197, lsl 48
  movk x13, #49763, lsl 16
  dup.2d v11, x12
  mov.16b v12, v5
  movk x13, #40165, lsl 32
  fmla.2d v12, v8, v11
  movk x13, #24776, lsl 48
  fsub.2d v13, v6, v12
  subs x9, x0, x9
  sbcs x11, x1, x11
  sbcs x10, x2, x10
  sbcs x12, x3, x13
  fmla.2d v13, v8, v11
  add.2d v2, v2, v12
  tst x3, #9223372036854775808
  csel x0, x9, x0, mi
  csel x1, x11, x1, mi
  csel x2, x10, x2, mi
  csel x3, x12, x3, mi
  add.2d v1, v1, v13
  mul x9, x4, x4
  mov x10, #17708
  umulh x11, x4, x4
  movk x10, #43915, lsl 16
  mul x12, x4, x5
  movk x10, #64348, lsl 32
  movk x10, #17188, lsl 48
  umulh x13, x4, x5
  dup.2d v11, x10
  adds x10, x12, x11
  cinc x11, x13, hs
  mov.16b v12, v5
  mul x14, x4, x6
  fmla.2d v12, v8, v11
  fsub.2d v13, v6, v12
  umulh x15, x4, x6
  fmla.2d v13, v8, v11
  adds x11, x14, x11
  cinc x16, x15, hs
  add.2d v7, v7, v12
  mul x17, x4, x7
  add.2d v2, v2, v13
  umulh x4, x4, x7
  mov x20, #29184
  movk x20, #20789, lsl 16
  adds x16, x17, x16
  cinc x21, x4, hs
  movk x20, #19197, lsl 32
  adds x10, x12, x10
  cinc x12, x13, hs
  movk x20, #17083, lsl 48
  mul x13, x5, x5
  dup.2d v11, x20
  mov.16b v12, v5
  umulh x20, x5, x5
  fmla.2d v12, v8, v11
  adds x12, x13, x12
  cinc x13, x20, hs
  fsub.2d v13, v6, v12
  adds x11, x12, x11
  cinc x12, x13, hs
  fmla.2d v13, v8, v11
  mul x13, x5, x6
  add.2d v3, v3, v12
  add.2d v7, v7, v13
  umulh x20, x5, x6
  ucvtf.2d v8, v10
  adds x12, x13, x12
  cinc x22, x20, hs
  mov x23, #58856
  adds x12, x12, x16
  cinc x16, x22, hs
  movk x23, #14953, lsl 16
  movk x23, #15155, lsl 32
  mul x22, x5, x7
  movk x23, #17181, lsl 48
  umulh x5, x5, x7
  dup.2d v10, x23
  adds x16, x22, x16
  cinc x23, x5, hs
  mov.16b v11, v5
  adds x16, x16, x21
  cinc x21, x23, hs
  fmla.2d v11, v8, v10
  fsub.2d v12, v6, v11
  adds x11, x14, x11
  cinc x14, x15, hs
  fmla.2d v12, v8, v10
  adds x13, x13, x14
  cinc x14, x20, hs
  add.2d v0, v0, v11
  adds x12, x13, x12
  cinc x13, x14, hs
  add.2d v9, v9, v12
  mov x14, #35392
  mul x15, x6, x6
  movk x14, #12477, lsl 16
  umulh x20, x6, x6
  movk x14, #56780, lsl 32
  adds x13, x15, x13
  cinc x15, x20, hs
  movk x14, #17142, lsl 48
  adds x13, x13, x16
  cinc x15, x15, hs
  dup.2d v10, x14
  mov.16b v11, v5
  mul x14, x6, x7
  fmla.2d v11, v8, v10
  umulh x6, x6, x7
  fsub.2d v12, v6, v11
  adds x15, x14, x15
  cinc x16, x6, hs
  fmla.2d v12, v8, v10
  add.2d v1, v1, v11
  adds x15, x15, x21
  cinc x16, x16, hs
  add.2d v0, v0, v12
  adds x12, x17, x12
  cinc x4, x4, hs
  mov x17, #9848
  adds x4, x22, x4
  cinc x5, x5, hs
  movk x17, #54501, lsl 16
  adds x4, x4, x13
  cinc x5, x5, hs
  movk x17, #31540, lsl 32
  movk x17, #17170, lsl 48
  adds x5, x14, x5
  cinc x6, x6, hs
  dup.2d v10, x17
  adds x5, x5, x15
  cinc x6, x6, hs
  mov.16b v11, v5
  mul x13, x7, x7
  fmla.2d v11, v8, v10
  fsub.2d v12, v6, v11
  umulh x7, x7, x7
  fmla.2d v12, v8, v10
  adds x6, x13, x6
  cinc x7, x7, hs
  add.2d v2, v2, v11
  adds x6, x6, x16
  cinc x7, x7, hs
  add.2d v1, v1, v12
  mov x13, #48718
  mov x14, #9584
  movk x14, #63883, lsl 16
  movk x13, #4732, lsl 16
  movk x14, #18253, lsl 32
  movk x13, #45078, lsl 32
  movk x14, #17190, lsl 48
  movk x13, #39852, lsl 48
  dup.2d v10, x14
  mov.16b v11, v5
  mov x14, #16676
  fmla.2d v11, v8, v10
  movk x14, #12692, lsl 16
  fsub.2d v12, v6, v11
  movk x14, #20986, lsl 32
  fmla.2d v12, v8, v10
  movk x14, #2848, lsl 48
  add.2d v7, v7, v11
  add.2d v2, v2, v12
  mov x15, #51052
  mov x16, #51712
  movk x15, #24721, lsl 16
  movk x16, #16093, lsl 16
  movk x15, #61092, lsl 32
  movk x16, #30633, lsl 32
  movk x16, #17068, lsl 48
  movk x15, #45156, lsl 48
  dup.2d v10, x16
  mov x16, #3197
  mov.16b v11, v5
  movk x16, #18936, lsl 16
  fmla.2d v11, v8, v10
  movk x16, #10922, lsl 32
  fsub.2d v12, v6, v11
  fmla.2d v12, v8, v10
  movk x16, #11014, lsl 48
  add.2d v3, v3, v11
  mul x17, x13, x9
  add.2d v7, v7, v12
  umulh x13, x13, x9
  ucvtf.2d v4, v4
  mov x20, #34724
  adds x12, x17, x12
  cinc x13, x13, hs
  movk x20, #40393, lsl 16
  mul x17, x14, x9
  movk x20, #23752, lsl 32
  umulh x14, x14, x9
  movk x20, #17184, lsl 48
  adds x13, x17, x13
  cinc x14, x14, hs
  dup.2d v8, x20
  mov.16b v10, v5
  adds x4, x13, x4
  cinc x13, x14, hs
  fmla.2d v10, v4, v8
  mul x14, x15, x9
  fsub.2d v11, v6, v10
  umulh x15, x15, x9
  fmla.2d v11, v4, v8
  add.2d v0, v0, v10
  adds x13, x14, x13
  cinc x14, x15, hs
  add.2d v8, v9, v11
  adds x5, x13, x5
  cinc x13, x14, hs
  mov x14, #25532
  mul x15, x16, x9
  movk x14, #31025, lsl 16
  umulh x9, x16, x9
  movk x14, #10002, lsl 32
  movk x14, #17199, lsl 48
  adds x13, x15, x13
  cinc x9, x9, hs
  dup.2d v9, x14
  adds x6, x13, x6
  cinc x9, x9, hs
  mov.16b v10, v5
  add x7, x7, x9
  fmla.2d v10, v4, v9
  fsub.2d v11, v6, v10
  mov x9, #56431
  fmla.2d v11, v4, v9
  movk x9, #30457, lsl 16
  add.2d v1, v1, v10
  movk x9, #30012, lsl 32
  add.2d v0, v0, v11
  movk x9, #6382, lsl 48
  mov x13, #18830
  movk x13, #2465, lsl 16
  mov x14, #59151
  movk x13, #36348, lsl 32
  movk x14, #41769, lsl 16
  movk x13, #17194, lsl 48
  movk x14, #32276, lsl 32
  dup.2d v9, x13
  mov.16b v10, v5
  movk x14, #21677, lsl 48
  fmla.2d v10, v4, v9
  mov x13, #34015
  fsub.2d v11, v6, v10
  movk x13, #20342, lsl 16
  fmla.2d v11, v4, v9
  movk x13, #13935, lsl 32
  add.2d v2, v2, v10
  add.2d v1, v1, v11
  movk x13, #11030, lsl 48
  mov x15, #21566
  mov x16, #13689
  movk x15, #43708, lsl 16
  movk x16, #8159, lsl 16
  movk x15, #57685, lsl 32
  movk x15, #17185, lsl 48
  movk x16, #215, lsl 32
  dup.2d v9, x15
  movk x16, #4913, lsl 48
  mov.16b v10, v5
  mul x15, x9, x10
  fmla.2d v10, v4, v9
  umulh x9, x9, x10
  fsub.2d v11, v6, v10
  fmla.2d v11, v4, v9
  adds x12, x15, x12
  cinc x9, x9, hs
  add.2d v7, v7, v10
  mul x15, x14, x10
  add.2d v2, v2, v11
  umulh x14, x14, x10
  mov x17, #3072
  movk x17, #8058, lsl 16
  adds x9, x15, x9
  cinc x14, x14, hs
  movk x17, #46097, lsl 32
  adds x4, x9, x4
  cinc x9, x14, hs
  movk x17, #17047, lsl 48
  mul x14, x13, x10
  dup.2d v9, x17
  mov.16b v10, v5
  umulh x13, x13, x10
  fmla.2d v10, v4, v9
  adds x9, x14, x9
  cinc x13, x13, hs
  fsub.2d v11, v6, v10
  adds x5, x9, x5
  cinc x9, x13, hs
  fmla.2d v11, v4, v9
  mul x13, x16, x10
  add.2d v3, v3, v10
  add.2d v4, v7, v11
  umulh x10, x16, x10
  mov x14, #65535
  adds x9, x13, x9
  cinc x10, x10, hs
  movk x14, #61439, lsl 16
  adds x6, x9, x6
  cinc x9, x10, hs
  movk x14, #62867, lsl 32
  movk x14, #1, lsl 48
  add x7, x7, x9
  umov x9, v8.d[0]
  mov x10, #61005
  umov x13, v8.d[1]
  movk x10, #58262, lsl 16
  mul x9, x9, x14
  movk x10, #32851, lsl 32
  mul x13, x13, x14
  and x9, x9, x8
  movk x10, #11582, lsl 48
  and x8, x13, x8
  mov x13, #37581
  ins v7.d[0], x9
  ins v7.d[1], x8
  movk x13, #43836, lsl 16
  ucvtf.2d v7, v7
  mov x8, #16
  movk x13, #36286, lsl 32
  movk x8, #22847, lsl 32
  movk x13, #51783, lsl 48
  movk x8, #17151, lsl 48
  mov x9, #10899
  dup.2d v9, x8
  movk x9, #30709, lsl 16
  mov.16b v10, v5
  fmla.2d v10, v7, v9
  movk x9, #61551, lsl 32
  fsub.2d v11, v6, v10
  movk x9, #45784, lsl 48
  fmla.2d v11, v7, v9
  mov x8, #36612
  add.2d v0, v0, v10
  add.2d v8, v8, v11
  movk x8, #63402, lsl 16
  mov x14, #20728
  movk x8, #47623, lsl 32
  movk x14, #23588, lsl 16
  movk x8, #9430, lsl 48
  movk x14, #7790, lsl 32
  mul x15, x10, x11
  movk x14, #17170, lsl 48
  dup.2d v9, x14
  umulh x10, x10, x11
  mov.16b v10, v5
  adds x12, x15, x12
  cinc x10, x10, hs
  fmla.2d v10, v7, v9
  mul x14, x13, x11
  fsub.2d v11, v6, v10
  fmla.2d v11, v7, v9
  umulh x13, x13, x11
  add.2d v1, v1, v10
  adds x10, x14, x10
  cinc x13, x13, hs
  add.2d v0, v0, v11
  adds x4, x10, x4
  cinc x10, x13, hs
  mov x13, #16000
  mul x14, x9, x11
  movk x13, #53891, lsl 16
  movk x13, #5509, lsl 32
  umulh x9, x9, x11
  movk x13, #17144, lsl 48
  adds x10, x14, x10
  cinc x9, x9, hs
  dup.2d v9, x13
  adds x5, x10, x5
  cinc x9, x9, hs
  mov.16b v10, v5
  fmla.2d v10, v7, v9
  mul x10, x8, x11
  fsub.2d v11, v6, v10
  umulh x8, x8, x11
  fmla.2d v11, v7, v9
  adds x9, x10, x9
  cinc x8, x8, hs
  add.2d v2, v2, v10
  adds x6, x9, x6
  cinc x8, x8, hs
  add.2d v1, v1, v11
  mov x9, #46800
  add x7, x7, x8
  movk x9, #2568, lsl 16
  mov x8, #65535
  movk x9, #1335, lsl 32
  movk x8, #61439, lsl 16
  movk x9, #17188, lsl 48
  dup.2d v9, x9
  movk x8, #62867, lsl 32
  mov.16b v10, v5
  movk x8, #49889, lsl 48
  fmla.2d v10, v7, v9
  mul x8, x8, x12
  fsub.2d v11, v6, v10
  mov x9, #1
  fmla.2d v11, v7, v9
  add.2d v4, v4, v10
  movk x9, #61440, lsl 16
  add.2d v2, v2, v11
  movk x9, #62867, lsl 32
  mov x10, #39040
  movk x9, #17377, lsl 48
  movk x10, #14704, lsl 16
  movk x10, #12839, lsl 32
  mov x11, #28817
  movk x10, #17096, lsl 48
  movk x11, #31161, lsl 16
  dup.2d v9, x10
  movk x11, #59464, lsl 32
  mov.16b v5, v5
  movk x11, #10291, lsl 48
  fmla.2d v5, v7, v9
  fsub.2d v6, v6, v5
  mov x10, #22621
  fmla.2d v6, v7, v9
  movk x10, #33153, lsl 16
  add.2d v3, v3, v5
  movk x10, #17846, lsl 32
  add.2d v4, v4, v6
  mov x13, #140737488355328
  movk x10, #47184, lsl 48
  dup.2d v5, x13
  mov x13, #41001
  and.16b v5, v3, v5
  movk x13, #57649, lsl 16
  cmeq.2d v5, v5, #0
  movk x13, #20082, lsl 32
  mov x14, #2
  movk x14, #57344, lsl 16
  movk x13, #12388, lsl 48
  movk x14, #60199, lsl 32
  mul x15, x9, x8
  movk x14, #3, lsl 48
  umulh x9, x9, x8
  dup.2d v6, x14
  bic.16b v6, v6, v5
  cmn x15, x12
  cinc x9, x9, hs
  mov x12, #10364
  mul x14, x11, x8
  movk x12, #11794, lsl 16
  umulh x11, x11, x8
  movk x12, #3895, lsl 32
  adds x9, x14, x9
  cinc x11, x11, hs
  movk x12, #9, lsl 48
  dup.2d v7, x12
  adds x4, x9, x4
  cinc x9, x11, hs
  bic.16b v7, v7, v5
  mul x11, x10, x8
  mov x12, #26576
  umulh x10, x10, x8
  movk x12, #47696, lsl 16
  movk x12, #688, lsl 32
  adds x9, x11, x9
  cinc x10, x10, hs
  movk x12, #3, lsl 48
  adds x5, x9, x5
  cinc x9, x10, hs
  dup.2d v9, x12
  mul x10, x13, x8
  bic.16b v9, v9, v5
  umulh x8, x13, x8
  mov x11, #46800
  movk x11, #2568, lsl 16
  adds x9, x10, x9
  cinc x8, x8, hs
  movk x11, #1335, lsl 32
  adds x6, x9, x6
  cinc x8, x8, hs
  movk x11, #4, lsl 48
  add x7, x7, x8
  dup.2d v10, x11
  bic.16b v10, v10, v5
  mov x8, #2
  mov x9, #49763
  movk x8, #57344, lsl 16
  movk x9, #40165, lsl 16
  movk x8, #60199, lsl 32
  movk x9, #24776, lsl 32
  movk x8, #34755, lsl 48
  dup.2d v11, x9
  bic.16b v5, v11, v5
  mov x9, #57634
  sub.2d v0, v0, v6
  movk x9, #62322, lsl 16
  ssra.2d v0, v8, #52
  movk x9, #53392, lsl 32
  sub.2d v6, v1, v7
  ssra.2d v6, v0, #52
  movk x9, #20583, lsl 48
  sub.2d v7, v2, v9
  mov x10, #45242
  ssra.2d v7, v6, #52
  movk x10, #770, lsl 16
  sub.2d v4, v4, v10
  movk x10, #35693, lsl 32
  ssra.2d v4, v7, #52
  sub.2d v5, v3, v5
  movk x10, #28832, lsl 48
  ssra.2d v5, v4, #52
  mov x11, #16467
  ushr.2d v1, v6, #12
  movk x11, #49763, lsl 16
  ushr.2d v2, v7, #24
  ushr.2d v3, v4, #36
  movk x11, #40165, lsl 32
  sli.2d v0, v6, #52
  movk x11, #24776, lsl 48
  sli.2d v1, v7, #40
  subs x8, x4, x8
  sbcs x9, x5, x9
  sbcs x10, x6, x10
  sbcs x11, x7, x11
  sli.2d v2, v4, #28
  sli.2d v3, v5, #16
  tst x7, #9223372036854775808
  csel x4, x8, x4, mi
  csel x5, x9, x5, mi
  csel x6, x10, x6, mi
  csel x7, x11, x7, mi
