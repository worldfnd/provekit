// GENERATED FILE, DO NOT EDIT!
// in("x0") a[0], in("x1") a[1], in("x2") a[2], in("x3") a[3],
// in("x4") b[0], in("x5") b[1], in("x6") b[2], in("x7") b[3],
// in("v0") av[0], in("v1") av[1], in("v2") av[2], in("v3") av[3],
// in("v4") bv[0], in("v5") bv[1], in("v6") bv[2], in("v7") bv[3],
// lateout("x0") out[0], lateout("x1") out[1], lateout("x2") out[2], lateout("x3") out[3],
// lateout("v0") outv[0], lateout("v1") outv[1], lateout("v2") outv[2], lateout("v3") outv[3],
// lateout("x4") _, lateout("x5") _, lateout("x6") _, lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _, lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _, lateout("x15") _, lateout("x16") _, lateout("v4") _, lateout("v5") _, lateout("v6") _, lateout("v7") _, lateout("v8") _, lateout("v9") _, lateout("v10") _, lateout("v11") _, lateout("v12") _, lateout("v13") _, lateout("v14") _, lateout("v15") _, lateout("v16") _, lateout("v17") _, lateout("v18") _, lateout("v19") _, lateout("v20") _, lateout("v21") _, lateout("v22") _, lateout("v23") _, lateout("v24") _,
// lateout("lr") _
  mov x8, #4503599627370495
  dup.2d v8, x8
  mul x9, x0, x4
  mov x10, #5075556780046548992
  dup.2d v9, x10
  mov x10, #1
  umulh x11, x0, x4
  movk x10, #18032, lsl 48
  dup.2d v10, x10
  shl.2d v11, v1, #14
  mul x10, x1, x4
  shl.2d v12, v2, #26
  shl.2d v13, v3, #38
  ushr.2d v3, v3, #14
  umulh x12, x1, x4
  shl.2d v14, v0, #2
  usra.2d v11, v0, #50
  usra.2d v12, v1, #38
  adds x10, x10, x11
  cinc x11, x12, hs
  usra.2d v13, v2, #26
  and.16b v0, v14, v8
  and.16b v1, v11, v8
  mul x12, x2, x4
  and.16b v2, v12, v8
  and.16b v11, v13, v8
  shl.2d v12, v5, #14
  umulh x13, x2, x4
  shl.2d v13, v6, #26
  shl.2d v14, v7, #38
  ushr.2d v7, v7, #14
  adds x11, x12, x11
  cinc x12, x13, hs
  shl.2d v15, v4, #2
  usra.2d v12, v4, #50
  usra.2d v13, v5, #38
  mul x13, x3, x4
  usra.2d v14, v6, #26
  and.16b v4, v15, v8
  and.16b v5, v12, v8
  umulh x4, x3, x4
  and.16b v6, v13, v8
  and.16b v12, v14, v8
  mov x14, #13605374474286268416
  adds x12, x13, x12
  cinc x4, x4, hs
  dup.2d v13, x14
  mov x13, #6440147467139809280
  dup.2d v14, x13
  mul x13, x0, x5
  mov x14, #3688448094816436224
  dup.2d v15, x14
  mov x14, #9209861237972664320
  umulh x15, x0, x5
  dup.2d v16, x14
  mov x14, #12218265789056155648
  dup.2d v17, x14
  adds x10, x13, x10
  cinc x13, x15, hs
  mov x14, #17739678932212383744
  dup.2d v18, x14
  mov x14, #2301339409586323456
  mul x15, x1, x5
  dup.2d v19, x14
  mov x14, #7822752552742551552
  dup.2d v20, x14
  umulh x14, x1, x5
  mov x16, #5071053180419178496
  dup.2d v21, x16
  mov x16, #16352570246982270976
  adds x13, x15, x13
  cinc x14, x14, hs
  dup.2d v22, x16
  ucvtf.2d v0, v0
  ucvtf.2d v1, v1
  adds x11, x13, x11
  cinc x13, x14, hs
  ucvtf.2d v2, v2
  ucvtf.2d v11, v11
  ucvtf.2d v3, v3
  mul x14, x2, x5
  ucvtf.2d v4, v4
  ucvtf.2d v5, v5
  ucvtf.2d v6, v6
  umulh x15, x2, x5
  ucvtf.2d v12, v12
  ucvtf.2d v7, v7
  mov.16b v23, v9
  adds x13, x14, x13
  cinc x14, x15, hs
  fmla.2d v23, v0, v4
  fsub.2d v24, v10, v23
  fmla.2d v24, v0, v4
  adds x12, x13, x12
  cinc x13, x14, hs
  add.2d v15, v15, v23
  add.2d v13, v13, v24
  mov.16b v23, v9
  mul x14, x3, x5
  fmla.2d v23, v0, v5
  fsub.2d v24, v10, v23
  umulh x5, x3, x5
  fmla.2d v24, v0, v5
  add.2d v17, v17, v23
  add.2d v15, v15, v24
  adds x13, x14, x13
  cinc x5, x5, hs
  mov.16b v23, v9
  fmla.2d v23, v0, v6
  fsub.2d v24, v10, v23
  adds x4, x13, x4
  cinc x5, x5, hs
  fmla.2d v24, v0, v6
  add.2d v19, v19, v23
  add.2d v17, v17, v24
  mul x13, x0, x6
  mov.16b v23, v9
  fmla.2d v23, v0, v12
  fsub.2d v24, v10, v23
  umulh x14, x0, x6
  fmla.2d v24, v0, v12
  add.2d v21, v21, v23
  add.2d v19, v19, v24
  adds x11, x13, x11
  cinc x13, x14, hs
  mov.16b v23, v9
  fmla.2d v23, v0, v7
  fsub.2d v24, v10, v23
  mul x14, x1, x6
  fmla.2d v24, v0, v7
  add.2d v0, v22, v23
  add.2d v21, v21, v24
  umulh x15, x1, x6
  mov.16b v22, v9
  fmla.2d v22, v1, v4
  fsub.2d v23, v10, v22
  adds x13, x14, x13
  cinc x14, x15, hs
  fmla.2d v23, v1, v4
  add.2d v17, v17, v22
  add.2d v15, v15, v23
  adds x12, x13, x12
  cinc x13, x14, hs
  mov.16b v22, v9
  fmla.2d v22, v1, v5
  fsub.2d v23, v10, v22
  mul x14, x2, x6
  fmla.2d v23, v1, v5
  add.2d v19, v19, v22
  add.2d v17, v17, v23
  umulh x15, x2, x6
  mov.16b v22, v9
  fmla.2d v22, v1, v6
  fsub.2d v23, v10, v22
  adds x13, x14, x13
  cinc x14, x15, hs
  fmla.2d v23, v1, v6
  add.2d v21, v21, v22
  add.2d v19, v19, v23
  adds x4, x13, x4
  cinc x13, x14, hs
  mov.16b v22, v9
  fmla.2d v22, v1, v12
  fsub.2d v23, v10, v22
  mul x14, x3, x6
  fmla.2d v23, v1, v12
  add.2d v0, v0, v22
  add.2d v21, v21, v23
  umulh x6, x3, x6
  mov.16b v22, v9
  fmla.2d v22, v1, v7
  fsub.2d v23, v10, v22
  adds x13, x14, x13
  cinc x6, x6, hs
  fmla.2d v23, v1, v7
  add.2d v1, v20, v22
  add.2d v0, v0, v23
  adds x5, x13, x5
  cinc x6, x6, hs
  mov.16b v20, v9
  fmla.2d v20, v2, v4
  fsub.2d v22, v10, v20
  mul x13, x0, x7
  fmla.2d v22, v2, v4
  add.2d v19, v19, v20
  add.2d v17, v17, v22
  umulh x0, x0, x7
  mov.16b v20, v9
  fmla.2d v20, v2, v5
  fsub.2d v22, v10, v20
  adds x12, x13, x12
  cinc x0, x0, hs
  fmla.2d v22, v2, v5
  add.2d v20, v21, v20
  add.2d v19, v19, v22
  mul x13, x1, x7
  mov.16b v21, v9
  fmla.2d v21, v2, v6
  fsub.2d v22, v10, v21
  umulh x1, x1, x7
  fmla.2d v22, v2, v6
  add.2d v0, v0, v21
  add.2d v20, v20, v22
  adds x0, x13, x0
  cinc x1, x1, hs
  mov.16b v21, v9
  fmla.2d v21, v2, v12
  adds x0, x0, x4
  cinc x1, x1, hs
  fsub.2d v22, v10, v21
  fmla.2d v22, v2, v12
  add.2d v1, v1, v21
  mul x4, x2, x7
  add.2d v0, v0, v22
  mov.16b v21, v9
  fmla.2d v21, v2, v7
  umulh x2, x2, x7
  fsub.2d v22, v10, v21
  fmla.2d v22, v2, v7
  add.2d v2, v18, v21
  adds x1, x4, x1
  cinc x2, x2, hs
  add.2d v1, v1, v22
  mov.16b v18, v9
  fmla.2d v18, v11, v4
  adds x1, x1, x5
  cinc x2, x2, hs
  fsub.2d v21, v10, v18
  fmla.2d v21, v11, v4
  add.2d v18, v20, v18
  mul x4, x3, x7
  add.2d v19, v19, v21
  mov.16b v20, v9
  fmla.2d v20, v11, v5
  umulh x3, x3, x7
  fsub.2d v21, v10, v20
  fmla.2d v21, v11, v5
  add.2d v0, v0, v20
  adds x2, x4, x2
  cinc x3, x3, hs
  add.2d v18, v18, v21
  mov.16b v20, v9
  fmla.2d v20, v11, v6
  adds x2, x2, x6
  cinc x3, x3, hs
  fsub.2d v21, v10, v20
  fmla.2d v21, v11, v6
  add.2d v1, v1, v20
  mov x4, #48718
  add.2d v0, v0, v21
  mov.16b v20, v9
  fmla.2d v20, v11, v12
  movk x4, #4732, lsl 16
  fsub.2d v21, v10, v20
  fmla.2d v21, v11, v12
  add.2d v2, v2, v20
  movk x4, #45078, lsl 32
  add.2d v1, v1, v21
  mov.16b v20, v9
  fmla.2d v20, v11, v7
  movk x4, #39852, lsl 48
  fsub.2d v21, v10, v20
  fmla.2d v21, v11, v7
  add.2d v11, v16, v20
  mov x5, #16676
  add.2d v2, v2, v21
  mov.16b v16, v9
  fmla.2d v16, v3, v4
  movk x5, #12692, lsl 16
  fsub.2d v20, v10, v16
  fmla.2d v20, v3, v4
  add.2d v0, v0, v16
  movk x5, #20986, lsl 32
  add.2d v4, v18, v20
  mov.16b v16, v9
  fmla.2d v16, v3, v5
  movk x5, #2848, lsl 48
  fsub.2d v18, v10, v16
  fmla.2d v18, v3, v5
  add.2d v1, v1, v16
  mov x6, #51052
  add.2d v0, v0, v18
  mov.16b v5, v9
  fmla.2d v5, v3, v6
  movk x6, #24721, lsl 16
  fsub.2d v16, v10, v5
  fmla.2d v16, v3, v6
  add.2d v2, v2, v5
  movk x6, #61092, lsl 32
  add.2d v1, v1, v16
  mov.16b v5, v9
  fmla.2d v5, v3, v12
  movk x6, #45156, lsl 48
  fsub.2d v6, v10, v5
  fmla.2d v6, v3, v12
  add.2d v5, v11, v5
  mov x7, #3197
  add.2d v2, v2, v6
  mov.16b v6, v9
  fmla.2d v6, v3, v7
  movk x7, #18936, lsl 16
  fsub.2d v11, v10, v6
  fmla.2d v11, v3, v7
  movk x7, #10922, lsl 32
  add.2d v3, v14, v6
  add.2d v5, v5, v11
  usra.2d v15, v13, #52
  movk x7, #11014, lsl 48
  usra.2d v17, v15, #52
  usra.2d v19, v17, #52
  usra.2d v4, v19, #52
  mul x13, x4, x9
  and.16b v6, v13, v8
  and.16b v7, v15, v8
  and.16b v11, v17, v8
  umulh x4, x4, x9
  and.16b v8, v19, v8
  ucvtf.2d v6, v6
  mov x14, #37864
  adds x12, x13, x12
  cinc x4, x4, hs
  movk x14, #1815, lsl 16
  movk x14, #28960, lsl 32
  movk x14, #17153, lsl 48
  mul x13, x5, x9
  dup.2d v12, x14
  mov.16b v13, v9
  fmla.2d v13, v6, v12
  umulh x5, x5, x9
  fsub.2d v14, v10, v13
  fmla.2d v14, v6, v12
  add.2d v0, v0, v13
  adds x4, x13, x4
  cinc x5, x5, hs
  add.2d v4, v4, v14
  mov x13, #46128
  movk x13, #29964, lsl 16
  adds x0, x4, x0
  cinc x4, x5, hs
  movk x13, #7587, lsl 32
  movk x13, #17161, lsl 48
  dup.2d v12, x13
  mul x5, x6, x9
  mov.16b v13, v9
  fmla.2d v13, v6, v12
  fsub.2d v14, v10, v13
  umulh x6, x6, x9
  fmla.2d v14, v6, v12
  add.2d v1, v1, v13
  add.2d v0, v0, v14
  adds x4, x5, x4
  cinc x5, x6, hs
  mov x6, #52826
  movk x6, #57790, lsl 16
  movk x6, #55431, lsl 32
  adds x1, x4, x1
  cinc x4, x5, hs
  movk x6, #17196, lsl 48
  dup.2d v12, x6
  mov.16b v13, v9
  mul x5, x7, x9
  fmla.2d v13, v6, v12
  fsub.2d v14, v10, v13
  fmla.2d v14, v6, v12
  umulh x6, x7, x9
  add.2d v2, v2, v13
  add.2d v1, v1, v14
  mov x7, #31276
  adds x4, x5, x4
  cinc x5, x6, hs
  movk x7, #21262, lsl 16
  movk x7, #2304, lsl 32
  movk x7, #17182, lsl 48
  adds x2, x4, x2
  cinc x4, x5, hs
  dup.2d v12, x7
  mov.16b v13, v9
  fmla.2d v13, v6, v12
  add x3, x3, x4
  fsub.2d v14, v10, v13
  fmla.2d v14, v6, v12
  add.2d v5, v5, v13
  mov x4, #56431
  add.2d v2, v2, v14
  mov x5, #28672
  movk x5, #24515, lsl 16
  movk x4, #30457, lsl 16
  movk x5, #54929, lsl 32
  movk x5, #17064, lsl 48
  dup.2d v12, x5
  movk x4, #30012, lsl 32
  mov.16b v13, v9
  fmla.2d v13, v6, v12
  fsub.2d v14, v10, v13
  movk x4, #6382, lsl 48
  fmla.2d v14, v6, v12
  add.2d v3, v3, v13
  add.2d v5, v5, v14
  mov x5, #59151
  ucvtf.2d v6, v7
  mov x6, #44768
  movk x6, #51919, lsl 16
  movk x5, #41769, lsl 16
  movk x6, #6346, lsl 32
  movk x6, #17133, lsl 48
  movk x5, #32276, lsl 32
  dup.2d v7, x6
  mov.16b v12, v9
  fmla.2d v12, v6, v7
  movk x5, #21677, lsl 48
  fsub.2d v13, v10, v12
  fmla.2d v13, v6, v7
  add.2d v0, v0, v12
  mov x6, #34015
  add.2d v4, v4, v13
  mov x7, #47492
  movk x7, #23630, lsl 16
  movk x6, #20342, lsl 16
  movk x7, #49985, lsl 32
  movk x7, #17168, lsl 48
  dup.2d v7, x7
  movk x6, #13935, lsl 32
  mov.16b v12, v9
  fmla.2d v12, v6, v7
  fsub.2d v13, v10, v12
  movk x6, #11030, lsl 48
  fmla.2d v13, v6, v7
  add.2d v1, v1, v12
  add.2d v0, v0, v13
  mov x7, #13689
  mov x9, #57936
  movk x9, #54828, lsl 16
  movk x9, #18292, lsl 32
  movk x7, #8159, lsl 16
  movk x9, #17197, lsl 48
  dup.2d v7, x9
  mov.16b v12, v9
  movk x7, #215, lsl 32
  fmla.2d v12, v6, v7
  fsub.2d v13, v10, v12
  fmla.2d v13, v6, v7
  movk x7, #4913, lsl 48
  add.2d v2, v2, v12
  add.2d v1, v1, v13
  mov x9, #17708
  mul x13, x4, x10
  movk x9, #43915, lsl 16
  movk x9, #64348, lsl 32
  movk x9, #17188, lsl 48
  umulh x4, x4, x10
  dup.2d v7, x9
  mov.16b v12, v9
  fmla.2d v12, v6, v7
  adds x9, x13, x12
  cinc x4, x4, hs
  fsub.2d v13, v10, v12
  fmla.2d v13, v6, v7
  add.2d v5, v5, v12
  mul x12, x5, x10
  add.2d v2, v2, v13
  mov x13, #29184
  movk x13, #20789, lsl 16
  umulh x5, x5, x10
  movk x13, #19197, lsl 32
  movk x13, #17083, lsl 48
  dup.2d v7, x13
  adds x4, x12, x4
  cinc x5, x5, hs
  mov.16b v12, v9
  fmla.2d v12, v6, v7
  fsub.2d v13, v10, v12
  adds x0, x4, x0
  cinc x4, x5, hs
  fmla.2d v13, v6, v7
  add.2d v3, v3, v12
  add.2d v5, v5, v13
  mul x5, x6, x10
  ucvtf.2d v6, v11
  mov x12, #58856
  movk x12, #14953, lsl 16
  umulh x6, x6, x10
  movk x12, #15155, lsl 32
  movk x12, #17181, lsl 48
  dup.2d v7, x12
  adds x4, x5, x4
  cinc x5, x6, hs
  mov.16b v11, v9
  fmla.2d v11, v6, v7
  fsub.2d v12, v10, v11
  adds x1, x4, x1
  cinc x4, x5, hs
  fmla.2d v12, v6, v7
  add.2d v0, v0, v11
  add.2d v4, v4, v12
  mul x5, x7, x10
  mov x6, #35392
  movk x6, #12477, lsl 16
  movk x6, #56780, lsl 32
  umulh x7, x7, x10
  movk x6, #17142, lsl 48
  dup.2d v7, x6
  mov.16b v11, v9
  adds x4, x5, x4
  cinc x5, x7, hs
  fmla.2d v11, v6, v7
  fsub.2d v12, v10, v11
  adds x2, x4, x2
  cinc x4, x5, hs
  fmla.2d v12, v6, v7
  add.2d v1, v1, v11
  add.2d v0, v0, v12
  add x3, x3, x4
  mov x4, #9848
  movk x4, #54501, lsl 16
  movk x4, #31540, lsl 32
  mov x5, #61005
  movk x4, #17170, lsl 48
  dup.2d v7, x4
  mov.16b v11, v9
  movk x5, #58262, lsl 16
  fmla.2d v11, v6, v7
  fsub.2d v12, v10, v11
  fmla.2d v12, v6, v7
  movk x5, #32851, lsl 32
  add.2d v2, v2, v11
  add.2d v1, v1, v12
  mov x4, #9584
  movk x5, #11582, lsl 48
  movk x4, #63883, lsl 16
  movk x4, #18253, lsl 32
  movk x4, #17190, lsl 48
  mov x6, #37581
  dup.2d v7, x4
  mov.16b v11, v9
  fmla.2d v11, v6, v7
  movk x6, #43836, lsl 16
  fsub.2d v12, v10, v11
  fmla.2d v12, v6, v7
  add.2d v5, v5, v11
  movk x6, #36286, lsl 32
  add.2d v2, v2, v12
  mov x4, #51712
  movk x4, #16093, lsl 16
  movk x6, #51783, lsl 48
  movk x4, #30633, lsl 32
  movk x4, #17068, lsl 48
  dup.2d v7, x4
  mov x4, #10899
  mov.16b v11, v9
  fmla.2d v11, v6, v7
  fsub.2d v12, v10, v11
  movk x4, #30709, lsl 16
  fmla.2d v12, v6, v7
  add.2d v3, v3, v11
  add.2d v5, v5, v12
  movk x4, #61551, lsl 32
  ucvtf.2d v6, v8
  mov x7, #34724
  movk x7, #40393, lsl 16
  movk x4, #45784, lsl 48
  movk x7, #23752, lsl 32
  movk x7, #17184, lsl 48
  dup.2d v7, x7
  mov x7, #36612
  mov.16b v8, v9
  fmla.2d v8, v6, v7
  fsub.2d v11, v10, v8
  movk x7, #63402, lsl 16
  fmla.2d v11, v6, v7
  add.2d v0, v0, v8
  add.2d v4, v4, v11
  movk x7, #47623, lsl 32
  mov x10, #25532
  movk x10, #31025, lsl 16
  movk x10, #10002, lsl 32
  movk x7, #9430, lsl 48
  movk x10, #17199, lsl 48
  dup.2d v7, x10
  mov.16b v8, v9
  mul x10, x5, x11
  fmla.2d v8, v6, v7
  fsub.2d v11, v10, v8
  fmla.2d v11, v6, v7
  umulh x5, x5, x11
  add.2d v1, v1, v8
  add.2d v0, v0, v11
  mov x12, #18830
  adds x9, x10, x9
  cinc x5, x5, hs
  movk x12, #2465, lsl 16
  movk x12, #36348, lsl 32
  movk x12, #17194, lsl 48
  mul x10, x6, x11
  dup.2d v7, x12
  mov.16b v8, v9
  fmla.2d v8, v6, v7
  umulh x6, x6, x11
  fsub.2d v11, v10, v8
  fmla.2d v11, v6, v7
  adds x5, x10, x5
  cinc x6, x6, hs
  add.2d v2, v2, v8
  add.2d v1, v1, v11
  mov x10, #21566
  adds x0, x5, x0
  cinc x5, x6, hs
  movk x10, #43708, lsl 16
  movk x10, #57685, lsl 32
  movk x10, #17185, lsl 48
  mul x6, x4, x11
  dup.2d v7, x10
  mov.16b v8, v9
  fmla.2d v8, v6, v7
  umulh x4, x4, x11
  fsub.2d v11, v10, v8
  fmla.2d v11, v6, v7
  add.2d v5, v5, v8
  adds x5, x6, x5
  cinc x4, x4, hs
  add.2d v2, v2, v11
  mov x6, #3072
  movk x6, #8058, lsl 16
  adds x1, x5, x1
  cinc x4, x4, hs
  movk x6, #46097, lsl 32
  movk x6, #17047, lsl 48
  dup.2d v7, x6
  mul x5, x7, x11
  mov.16b v8, v9
  fmla.2d v8, v6, v7
  fsub.2d v11, v10, v8
  umulh x6, x7, x11
  fmla.2d v11, v6, v7
  add.2d v3, v3, v8
  add.2d v5, v5, v11
  adds x4, x5, x4
  cinc x5, x6, hs
  mov x6, #65535
  movk x6, #61439, lsl 16
  movk x6, #62867, lsl 32
  adds x2, x4, x2
  cinc x4, x5, hs
  movk x6, #1, lsl 48
  umov x5, v4.d[0]
  umov x7, v4.d[1]
  add x3, x3, x4
  mul x4, x5, x6
  mul x5, x7, x6
  and x4, x4, x8
  mov x6, #65535
  and x5, x5, x8
  ins v6.d[0], x4
  ins v6.d[1], x5
  ucvtf.2d v6, v6
  movk x6, #61439, lsl 16
  mov x4, #16
  movk x4, #22847, lsl 32
  movk x4, #17151, lsl 48
  movk x6, #62867, lsl 32
  dup.2d v7, x4
  mov.16b v8, v9
  fmla.2d v8, v6, v7
  movk x6, #49889, lsl 48
  fsub.2d v11, v10, v8
  fmla.2d v11, v6, v7
  add.2d v0, v0, v8
  mul x4, x6, x9
  add.2d v4, v4, v11
  mov x5, #20728
  movk x5, #23588, lsl 16
  mov x6, #1
  movk x5, #7790, lsl 32
  movk x5, #17170, lsl 48
  dup.2d v7, x5
  movk x6, #61440, lsl 16
  mov.16b v8, v9
  fmla.2d v8, v6, v7
  fsub.2d v11, v10, v8
  movk x6, #62867, lsl 32
  fmla.2d v11, v6, v7
  add.2d v1, v1, v8
  add.2d v0, v0, v11
  movk x6, #17377, lsl 48
  mov x5, #16000
  movk x5, #53891, lsl 16
  movk x5, #5509, lsl 32
  mov x7, #28817
  movk x5, #17144, lsl 48
  dup.2d v7, x5
  mov.16b v8, v9
  movk x7, #31161, lsl 16
  fmla.2d v8, v6, v7
  fsub.2d v11, v10, v8
  fmla.2d v11, v6, v7
  movk x7, #59464, lsl 32
  add.2d v2, v2, v8
  add.2d v1, v1, v11
  mov x5, #46800
  movk x7, #10291, lsl 48
  movk x5, #2568, lsl 16
  movk x5, #1335, lsl 32
  mov x8, #22621
  movk x5, #17188, lsl 48
  dup.2d v7, x5
  mov.16b v8, v9
  movk x8, #33153, lsl 16
  fmla.2d v8, v6, v7
  fsub.2d v11, v10, v8
  fmla.2d v11, v6, v7
  movk x8, #17846, lsl 32
  add.2d v5, v5, v8
  add.2d v2, v2, v11
  mov x5, #39040
  movk x8, #47184, lsl 48
  movk x5, #14704, lsl 16
  movk x5, #12839, lsl 32
  movk x5, #17096, lsl 48
  mov x10, #41001
  dup.2d v7, x5
  mov.16b v8, v9
  fmla.2d v8, v6, v7
  movk x10, #57649, lsl 16
  fsub.2d v9, v10, v8
  fmla.2d v9, v6, v7
  add.2d v3, v3, v8
  movk x10, #20082, lsl 32
  add.2d v5, v5, v9
  mov x5, #140737488355328
  dup.2d v6, x5
  movk x10, #12388, lsl 48
  and.16b v6, v3, v6
  cmeq.2d v6, v6, #0
  mov x5, #2
  mul x11, x6, x4
  movk x5, #57344, lsl 16
  movk x5, #60199, lsl 32
  movk x5, #3, lsl 48
  umulh x6, x6, x4
  dup.2d v7, x5
  bic.16b v7, v7, v6
  mov x5, #10364
  cmn x11, x9
  cinc x6, x6, hs
  movk x5, #11794, lsl 16
  movk x5, #3895, lsl 32
  movk x5, #9, lsl 48
  mul x9, x7, x4
  dup.2d v8, x5
  bic.16b v8, v8, v6
  mov x5, #26576
  umulh x7, x7, x4
  movk x5, #47696, lsl 16
  movk x5, #688, lsl 32
  movk x5, #3, lsl 48
  adds x6, x9, x6
  cinc x7, x7, hs
  dup.2d v9, x5
  bic.16b v9, v9, v6
  mov x5, #46800
  adds x0, x6, x0
  cinc x6, x7, hs
  movk x5, #2568, lsl 16
  movk x5, #1335, lsl 32
  movk x5, #4, lsl 48
  mul x7, x8, x4
  dup.2d v10, x5
  bic.16b v10, v10, v6
  mov x5, #49763
  umulh x8, x8, x4
  movk x5, #40165, lsl 16
  movk x5, #24776, lsl 32
  dup.2d v11, x5
  adds x5, x7, x6
  cinc x6, x8, hs
  bic.16b v6, v11, v6
  sub.2d v0, v0, v7
  ssra.2d v0, v4, #52
  adds x1, x5, x1
  cinc x5, x6, hs
  sub.2d v4, v1, v8
  ssra.2d v4, v0, #52
  sub.2d v7, v2, v9
  mul x6, x10, x4
  ssra.2d v7, v4, #52
  sub.2d v5, v5, v10
  ssra.2d v5, v7, #52
  umulh x4, x10, x4
  sub.2d v6, v3, v6
  ssra.2d v6, v5, #52
  ushr.2d v1, v4, #12
  adds x5, x6, x5
  cinc x4, x4, hs
  ushr.2d v2, v7, #24
  ushr.2d v3, v5, #36
  sli.2d v0, v4, #52
  adds x2, x5, x2
  cinc x4, x4, hs
  sli.2d v1, v7, #40
  sli.2d v2, v5, #28
  sli.2d v3, v6, #16
  add x3, x3, x4
