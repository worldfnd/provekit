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
  dup.2d v5, x11
  mul x11, x0, x1
  mov x12, #1
  umulh x13, x0, x1
  movk x12, #18032, lsl 48
  dup.2d v6, x12
  adds x10, x11, x10
  cinc x12, x13, hs
  shl.2d v7, v1, #14
  mul x14, x0, x2
  shl.2d v8, v2, #26
  umulh x15, x0, x2
  shl.2d v9, v3, #38
  ushr.2d v3, v3, #14
  adds x12, x14, x12
  cinc x16, x15, hs
  shl.2d v10, v0, #2
  mul x17, x0, x3
  usra.2d v7, v0, #50
  usra.2d v8, v1, #38
  umulh x0, x0, x3
  usra.2d v9, v2, #26
  adds x16, x17, x16
  cinc x20, x0, hs
  and.16b v0, v10, v4
  and.16b v1, v7, v4
  adds x10, x11, x10
  cinc x11, x13, hs
  and.16b v2, v8, v4
  mul x13, x1, x1
  and.16b v7, v9, v4
  umulh x21, x1, x1
  mov x22, #13605374474286268416
  dup.2d v8, x22
  adds x11, x13, x11
  cinc x13, x21, hs
  mov x21, #6440147467139809280
  adds x11, x11, x12
  cinc x12, x13, hs
  dup.2d v9, x21
  mov x13, #3688448094816436224
  mul x21, x1, x2
  dup.2d v10, x13
  umulh x13, x1, x2
  mov x22, #9209861237972664320
  adds x12, x21, x12
  cinc x23, x13, hs
  dup.2d v11, x22
  mov x22, #12218265789056155648
  adds x12, x12, x16
  cinc x16, x23, hs
  dup.2d v12, x22
  mul x22, x1, x3
  mov x23, #17739678932212383744
  dup.2d v13, x23
  umulh x1, x1, x3
  mov x23, #2301339409586323456
  adds x16, x22, x16
  cinc x24, x1, hs
  dup.2d v14, x23
  mov x23, #7822752552742551552
  adds x16, x16, x20
  cinc x20, x24, hs
  dup.2d v15, x23
  adds x11, x14, x11
  cinc x14, x15, hs
  mov x15, #5071053180419178496
  adds x14, x21, x14
  cinc x13, x13, hs
  dup.2d v16, x15
  mov x15, #16352570246982270976
  adds x12, x14, x12
  cinc x13, x13, hs
  dup.2d v17, x15
  mul x14, x2, x2
  ucvtf.2d v0, v0
  ucvtf.2d v1, v1
  umulh x15, x2, x2
  ucvtf.2d v2, v2
  adds x13, x14, x13
  cinc x14, x15, hs
  ucvtf.2d v7, v7
  adds x13, x13, x16
  cinc x14, x14, hs
  ucvtf.2d v3, v3
  mov.16b v18, v5
  mul x15, x2, x3
  fmla.2d v18, v0, v0
  umulh x2, x2, x3
  fsub.2d v19, v6, v18
  fmla.2d v19, v0, v0
  adds x14, x15, x14
  cinc x16, x2, hs
  add.2d v10, v10, v18
  adds x14, x14, x20
  cinc x16, x16, hs
  add.2d v8, v8, v19
  mov.16b v18, v5
  adds x12, x17, x12
  cinc x0, x0, hs
  fmla.2d v18, v0, v1
  adds x0, x22, x0
  cinc x1, x1, hs
  fsub.2d v19, v6, v18
  adds x0, x0, x13
  cinc x1, x1, hs
  fmla.2d v19, v0, v1
  add.2d v18, v18, v18
  adds x1, x15, x1
  cinc x2, x2, hs
  add.2d v19, v19, v19
  adds x1, x1, x14
  cinc x2, x2, hs
  add.2d v12, v12, v18
  add.2d v10, v10, v19
  mul x13, x3, x3
  mov.16b v18, v5
  umulh x3, x3, x3
  fmla.2d v18, v0, v2
  adds x2, x13, x2
  cinc x3, x3, hs
  fsub.2d v19, v6, v18
  fmla.2d v19, v0, v2
  adds x2, x2, x16
  cinc x3, x3, hs
  add.2d v18, v18, v18
  mov x13, #48718
  add.2d v19, v19, v19
  add.2d v14, v14, v18
  movk x13, #4732, lsl 16
  add.2d v12, v12, v19
  movk x13, #45078, lsl 32
  mov.16b v18, v5
  fmla.2d v18, v0, v7
  movk x13, #39852, lsl 48
  fsub.2d v19, v6, v18
  mov x14, #16676
  fmla.2d v19, v0, v7
  movk x14, #12692, lsl 16
  add.2d v18, v18, v18
  add.2d v19, v19, v19
  movk x14, #20986, lsl 32
  add.2d v16, v16, v18
  movk x14, #2848, lsl 48
  add.2d v14, v14, v19
  mov.16b v18, v5
  mov x15, #51052
  fmla.2d v18, v0, v3
  movk x15, #24721, lsl 16
  fsub.2d v19, v6, v18
  movk x15, #61092, lsl 32
  fmla.2d v19, v0, v3
  add.2d v0, v18, v18
  movk x15, #45156, lsl 48
  add.2d v18, v19, v19
  mov x16, #3197
  add.2d v0, v17, v0
  add.2d v16, v16, v18
  movk x16, #18936, lsl 16
  mov.16b v17, v5
  movk x16, #10922, lsl 32
  fmla.2d v17, v1, v1
  fsub.2d v18, v6, v17
  movk x16, #11014, lsl 48
  fmla.2d v18, v1, v1
  mul x17, x13, x9
  add.2d v14, v14, v17
  umulh x13, x13, x9
  add.2d v12, v12, v18
  mov.16b v17, v5
  adds x12, x17, x12
  cinc x13, x13, hs
  fmla.2d v17, v1, v2
  mul x17, x14, x9
  fsub.2d v18, v6, v17
  fmla.2d v18, v1, v2
  umulh x14, x14, x9
  add.2d v17, v17, v17
  adds x13, x17, x13
  cinc x14, x14, hs
  add.2d v18, v18, v18
  add.2d v16, v16, v17
  adds x0, x13, x0
  cinc x13, x14, hs
  add.2d v14, v14, v18
  mul x14, x15, x9
  mov.16b v17, v5
  umulh x15, x15, x9
  fmla.2d v17, v1, v7
  fsub.2d v18, v6, v17
  adds x13, x14, x13
  cinc x14, x15, hs
  fmla.2d v18, v1, v7
  adds x1, x13, x1
  cinc x13, x14, hs
  add.2d v17, v17, v17
  add.2d v18, v18, v18
  mul x14, x16, x9
  add.2d v0, v0, v17
  umulh x9, x16, x9
  add.2d v16, v16, v18
  adds x13, x14, x13
  cinc x9, x9, hs
  mov.16b v17, v5
  fmla.2d v17, v1, v3
  adds x2, x13, x2
  cinc x9, x9, hs
  fsub.2d v18, v6, v17
  add x3, x3, x9
  fmla.2d v18, v1, v3
  add.2d v1, v17, v17
  mov x9, #56431
  add.2d v17, v18, v18
  movk x9, #30457, lsl 16
  add.2d v1, v15, v1
  add.2d v0, v0, v17
  movk x9, #30012, lsl 32
  mov.16b v15, v5
  movk x9, #6382, lsl 48
  fmla.2d v15, v2, v2
  mov x13, #59151
  fsub.2d v17, v6, v15
  fmla.2d v17, v2, v2
  movk x13, #41769, lsl 16
  add.2d v0, v0, v15
  movk x13, #32276, lsl 32
  add.2d v15, v16, v17
  mov.16b v16, v5
  movk x13, #21677, lsl 48
  fmla.2d v16, v2, v7
  mov x14, #34015
  fsub.2d v17, v6, v16
  movk x14, #20342, lsl 16
  fmla.2d v17, v2, v7
  add.2d v16, v16, v16
  movk x14, #13935, lsl 32
  add.2d v17, v17, v17
  movk x14, #11030, lsl 48
  add.2d v1, v1, v16
  add.2d v0, v0, v17
  mov x15, #13689
  mov.16b v16, v5
  movk x15, #8159, lsl 16
  fmla.2d v16, v2, v3
  fsub.2d v17, v6, v16
  movk x15, #215, lsl 32
  fmla.2d v17, v2, v3
  movk x15, #4913, lsl 48
  add.2d v2, v16, v16
  mul x16, x9, x10
  add.2d v16, v17, v17
  add.2d v2, v13, v2
  umulh x9, x9, x10
  add.2d v1, v1, v16
  adds x12, x16, x12
  cinc x9, x9, hs
  mov.16b v13, v5
  fmla.2d v13, v7, v7
  mul x16, x13, x10
  fsub.2d v16, v6, v13
  umulh x13, x13, x10
  fmla.2d v16, v7, v7
  adds x9, x16, x9
  cinc x13, x13, hs
  add.2d v2, v2, v13
  add.2d v1, v1, v16
  adds x0, x9, x0
  cinc x9, x13, hs
  mov.16b v13, v5
  mul x13, x14, x10
  fmla.2d v13, v7, v3
  fsub.2d v16, v6, v13
  umulh x14, x14, x10
  fmla.2d v16, v7, v3
  adds x9, x13, x9
  cinc x13, x14, hs
  add.2d v7, v13, v13
  add.2d v13, v16, v16
  adds x1, x9, x1
  cinc x9, x13, hs
  add.2d v7, v11, v7
  mul x13, x15, x10
  add.2d v2, v2, v13
  umulh x10, x15, x10
  mov.16b v11, v5
  fmla.2d v11, v3, v3
  adds x9, x13, x9
  cinc x10, x10, hs
  fsub.2d v13, v6, v11
  adds x2, x9, x2
  cinc x9, x10, hs
  fmla.2d v13, v3, v3
  add.2d v3, v9, v11
  add x3, x3, x9
  add.2d v7, v7, v13
  mov x9, #61005
  usra.2d v10, v8, #52
  movk x9, #58262, lsl 16
  usra.2d v12, v10, #52
  usra.2d v14, v12, #52
  movk x9, #32851, lsl 32
  usra.2d v15, v14, #52
  movk x9, #11582, lsl 48
  and.16b v8, v8, v4
  and.16b v9, v10, v4
  mov x10, #37581
  and.16b v10, v12, v4
  movk x10, #43836, lsl 16
  and.16b v4, v14, v4
  ucvtf.2d v8, v8
  movk x10, #36286, lsl 32
  mov x13, #37864
  movk x10, #51783, lsl 48
  movk x13, #1815, lsl 16
  mov x14, #10899
  movk x13, #28960, lsl 32
  movk x13, #17153, lsl 48
  movk x14, #30709, lsl 16
  dup.2d v11, x13
  movk x14, #61551, lsl 32
  mov.16b v12, v5
  fmla.2d v12, v8, v11
  movk x14, #45784, lsl 48
  fsub.2d v13, v6, v12
  mov x13, #36612
  fmla.2d v13, v8, v11
  add.2d v0, v0, v12
  movk x13, #63402, lsl 16
  add.2d v11, v15, v13
  movk x13, #47623, lsl 32
  mov x15, #46128
  movk x13, #9430, lsl 48
  movk x15, #29964, lsl 16
  movk x15, #7587, lsl 32
  mul x16, x9, x11
  movk x15, #17161, lsl 48
  umulh x9, x9, x11
  dup.2d v12, x15
  mov.16b v13, v5
  adds x12, x16, x12
  cinc x9, x9, hs
  fmla.2d v13, v8, v12
  mul x15, x10, x11
  fsub.2d v14, v6, v13
  umulh x10, x10, x11
  fmla.2d v14, v8, v12
  add.2d v1, v1, v13
  adds x9, x15, x9
  cinc x10, x10, hs
  add.2d v0, v0, v14
  adds x0, x9, x0
  cinc x9, x10, hs
  mov x10, #52826
  movk x10, #57790, lsl 16
  mul x15, x14, x11
  movk x10, #55431, lsl 32
  umulh x14, x14, x11
  movk x10, #17196, lsl 48
  dup.2d v12, x10
  adds x9, x15, x9
  cinc x10, x14, hs
  mov.16b v13, v5
  adds x1, x9, x1
  cinc x9, x10, hs
  fmla.2d v13, v8, v12
  mul x10, x13, x11
  fsub.2d v14, v6, v13
  fmla.2d v14, v8, v12
  umulh x11, x13, x11
  add.2d v2, v2, v13
  adds x9, x10, x9
  cinc x10, x11, hs
  add.2d v1, v1, v14
  mov x11, #31276
  adds x2, x9, x2
  cinc x9, x10, hs
  movk x11, #21262, lsl 16
  add x3, x3, x9
  movk x11, #2304, lsl 32
  mov x9, #65535
  movk x11, #17182, lsl 48
  dup.2d v12, x11
  movk x9, #61439, lsl 16
  mov.16b v13, v5
  movk x9, #62867, lsl 32
  fmla.2d v13, v8, v12
  fsub.2d v14, v6, v13
  movk x9, #49889, lsl 48
  fmla.2d v14, v8, v12
  mul x9, x9, x12
  add.2d v7, v7, v13
  add.2d v2, v2, v14
  mov x10, #1
  mov x11, #28672
  movk x10, #61440, lsl 16
  movk x11, #24515, lsl 16
  movk x10, #62867, lsl 32
  movk x11, #54929, lsl 32
  movk x11, #17064, lsl 48
  movk x10, #17377, lsl 48
  dup.2d v12, x11
  mov x11, #28817
  mov.16b v13, v5
  fmla.2d v13, v8, v12
  movk x11, #31161, lsl 16
  fsub.2d v14, v6, v13
  movk x11, #59464, lsl 32
  fmla.2d v14, v8, v12
  movk x11, #10291, lsl 48
  add.2d v3, v3, v13
  add.2d v7, v7, v14
  mov x13, #22621
  ucvtf.2d v8, v9
  movk x13, #33153, lsl 16
  mov x14, #44768
  movk x14, #51919, lsl 16
  movk x13, #17846, lsl 32
  movk x14, #6346, lsl 32
  movk x13, #47184, lsl 48
  movk x14, #17133, lsl 48
  dup.2d v9, x14
  mov x14, #41001
  mov.16b v12, v5
  movk x14, #57649, lsl 16
  fmla.2d v12, v8, v9
  movk x14, #20082, lsl 32
  fsub.2d v13, v6, v12
  fmla.2d v13, v8, v9
  movk x14, #12388, lsl 48
  add.2d v0, v0, v12
  mul x15, x10, x9
  add.2d v9, v11, v13
  mov x16, #47492
  umulh x10, x10, x9
  movk x16, #23630, lsl 16
  cmn x15, x12
  cinc x10, x10, hs
  movk x16, #49985, lsl 32
  mul x12, x11, x9
  movk x16, #17168, lsl 48
  dup.2d v11, x16
  umulh x11, x11, x9
  mov.16b v12, v5
  adds x10, x12, x10
  cinc x11, x11, hs
  fmla.2d v12, v8, v11
  fsub.2d v13, v6, v12
  adds x0, x10, x0
  cinc x10, x11, hs
  fmla.2d v13, v8, v11
  mul x11, x13, x9
  add.2d v1, v1, v12
  add.2d v0, v0, v13
  umulh x12, x13, x9
  mov x13, #57936
  adds x10, x11, x10
  cinc x11, x12, hs
  movk x13, #54828, lsl 16
  adds x1, x10, x1
  cinc x10, x11, hs
  movk x13, #18292, lsl 32
  movk x13, #17197, lsl 48
  mul x11, x14, x9
  dup.2d v11, x13
  umulh x9, x14, x9
  mov.16b v12, v5
  fmla.2d v12, v8, v11
  adds x10, x11, x10
  cinc x9, x9, hs
  fsub.2d v13, v6, v12
  adds x2, x10, x2
  cinc x9, x9, hs
  fmla.2d v13, v8, v11
  add.2d v2, v2, v12
  add x3, x3, x9
  add.2d v1, v1, v13
  mul x9, x4, x4
  mov x10, #17708
  umulh x11, x4, x4
  movk x10, #43915, lsl 16
  movk x10, #64348, lsl 32
  mul x12, x4, x5
  movk x10, #17188, lsl 48
  umulh x13, x4, x5
  dup.2d v11, x10
  mov.16b v12, v5
  adds x10, x12, x11
  cinc x11, x13, hs
  fmla.2d v12, v8, v11
  mul x14, x4, x6
  fsub.2d v13, v6, v12
  umulh x15, x4, x6
  fmla.2d v13, v8, v11
  add.2d v7, v7, v12
  adds x11, x14, x11
  cinc x16, x15, hs
  add.2d v2, v2, v13
  mul x17, x4, x7
  mov x20, #29184
  movk x20, #20789, lsl 16
  umulh x4, x4, x7
  movk x20, #19197, lsl 32
  adds x16, x17, x16
  cinc x21, x4, hs
  movk x20, #17083, lsl 48
  dup.2d v11, x20
  adds x10, x12, x10
  cinc x12, x13, hs
  mov.16b v12, v5
  mul x13, x5, x5
  fmla.2d v12, v8, v11
  umulh x20, x5, x5
  fsub.2d v13, v6, v12
  fmla.2d v13, v8, v11
  adds x12, x13, x12
  cinc x13, x20, hs
  add.2d v3, v3, v12
  adds x11, x12, x11
  cinc x12, x13, hs
  add.2d v7, v7, v13
  ucvtf.2d v8, v10
  mul x13, x5, x6
  mov x20, #58856
  umulh x22, x5, x6
  movk x20, #14953, lsl 16
  adds x12, x13, x12
  cinc x23, x22, hs
  movk x20, #15155, lsl 32
  movk x20, #17181, lsl 48
  adds x12, x12, x16
  cinc x16, x23, hs
  dup.2d v10, x20
  mul x20, x5, x7
  mov.16b v11, v5
  fmla.2d v11, v8, v10
  umulh x5, x5, x7
  fsub.2d v12, v6, v11
  adds x16, x20, x16
  cinc x23, x5, hs
  fmla.2d v12, v8, v10
  add.2d v0, v0, v11
  adds x16, x16, x21
  cinc x21, x23, hs
  add.2d v9, v9, v12
  adds x11, x14, x11
  cinc x14, x15, hs
  mov x15, #35392
  adds x13, x13, x14
  cinc x14, x22, hs
  movk x15, #12477, lsl 16
  movk x15, #56780, lsl 32
  adds x12, x13, x12
  cinc x13, x14, hs
  movk x15, #17142, lsl 48
  mul x14, x6, x6
  dup.2d v10, x15
  mov.16b v11, v5
  umulh x15, x6, x6
  fmla.2d v11, v8, v10
  adds x13, x14, x13
  cinc x14, x15, hs
  fsub.2d v12, v6, v11
  adds x13, x13, x16
  cinc x14, x14, hs
  fmla.2d v12, v8, v10
  add.2d v1, v1, v11
  mul x15, x6, x7
  add.2d v0, v0, v12
  umulh x6, x6, x7
  mov x16, #9848
  movk x16, #54501, lsl 16
  adds x14, x15, x14
  cinc x22, x6, hs
  movk x16, #31540, lsl 32
  adds x14, x14, x21
  cinc x21, x22, hs
  movk x16, #17170, lsl 48
  dup.2d v10, x16
  adds x12, x17, x12
  cinc x4, x4, hs
  mov.16b v11, v5
  adds x4, x20, x4
  cinc x5, x5, hs
  fmla.2d v11, v8, v10
  adds x4, x4, x13
  cinc x5, x5, hs
  fsub.2d v12, v6, v11
  fmla.2d v12, v8, v10
  adds x5, x15, x5
  cinc x6, x6, hs
  add.2d v2, v2, v11
  adds x5, x5, x14
  cinc x6, x6, hs
  add.2d v1, v1, v12
  mov x13, #9584
  mul x14, x7, x7
  movk x13, #63883, lsl 16
  umulh x7, x7, x7
  movk x13, #18253, lsl 32
  adds x6, x14, x6
  cinc x7, x7, hs
  movk x13, #17190, lsl 48
  dup.2d v10, x13
  adds x6, x6, x21
  cinc x7, x7, hs
  mov.16b v11, v5
  mov x13, #48718
  fmla.2d v11, v8, v10
  fsub.2d v12, v6, v11
  movk x13, #4732, lsl 16
  fmla.2d v12, v8, v10
  movk x13, #45078, lsl 32
  add.2d v7, v7, v11
  add.2d v2, v2, v12
  movk x13, #39852, lsl 48
  mov x14, #51712
  mov x15, #16676
  movk x14, #16093, lsl 16
  movk x15, #12692, lsl 16
  movk x14, #30633, lsl 32
  movk x14, #17068, lsl 48
  movk x15, #20986, lsl 32
  dup.2d v10, x14
  movk x15, #2848, lsl 48
  mov.16b v11, v5
  fmla.2d v11, v8, v10
  mov x14, #51052
  fsub.2d v12, v6, v11
  movk x14, #24721, lsl 16
  fmla.2d v12, v8, v10
  movk x14, #61092, lsl 32
  add.2d v3, v3, v11
  add.2d v7, v7, v12
  movk x14, #45156, lsl 48
  ucvtf.2d v4, v4
  mov x16, #3197
  mov x17, #34724
  movk x17, #40393, lsl 16
  movk x16, #18936, lsl 16
  movk x17, #23752, lsl 32
  movk x16, #10922, lsl 32
  movk x17, #17184, lsl 48
  dup.2d v8, x17
  movk x16, #11014, lsl 48
  mov.16b v10, v5
  mul x17, x13, x9
  fmla.2d v10, v4, v8
  umulh x13, x13, x9
  fsub.2d v11, v6, v10
  fmla.2d v11, v4, v8
  adds x12, x17, x12
  cinc x13, x13, hs
  add.2d v0, v0, v10
  mul x17, x15, x9
  add.2d v8, v9, v11
  mov x20, #25532
  umulh x15, x15, x9
  movk x20, #31025, lsl 16
  adds x13, x17, x13
  cinc x15, x15, hs
  movk x20, #10002, lsl 32
  movk x20, #17199, lsl 48
  adds x4, x13, x4
  cinc x13, x15, hs
  dup.2d v9, x20
  mul x15, x14, x9
  mov.16b v10, v5
  umulh x14, x14, x9
  fmla.2d v10, v4, v9
  fsub.2d v11, v6, v10
  adds x13, x15, x13
  cinc x14, x14, hs
  fmla.2d v11, v4, v9
  adds x5, x13, x5
  cinc x13, x14, hs
  add.2d v1, v1, v10
  add.2d v0, v0, v11
  mul x14, x16, x9
  mov x15, #18830
  umulh x9, x16, x9
  movk x15, #2465, lsl 16
  adds x13, x14, x13
  cinc x9, x9, hs
  movk x15, #36348, lsl 32
  movk x15, #17194, lsl 48
  adds x6, x13, x6
  cinc x9, x9, hs
  dup.2d v9, x15
  add x7, x7, x9
  mov.16b v10, v5
  fmla.2d v10, v4, v9
  mov x9, #56431
  fsub.2d v11, v6, v10
  movk x9, #30457, lsl 16
  fmla.2d v11, v4, v9
  add.2d v2, v2, v10
  movk x9, #30012, lsl 32
  add.2d v1, v1, v11
  movk x9, #6382, lsl 48
  mov x13, #21566
  mov x14, #59151
  movk x13, #43708, lsl 16
  movk x13, #57685, lsl 32
  movk x14, #41769, lsl 16
  movk x13, #17185, lsl 48
  movk x14, #32276, lsl 32
  dup.2d v9, x13
  mov.16b v10, v5
  movk x14, #21677, lsl 48
  fmla.2d v10, v4, v9
  mov x13, #34015
  fsub.2d v11, v6, v10
  movk x13, #20342, lsl 16
  fmla.2d v11, v4, v9
  add.2d v7, v7, v10
  movk x13, #13935, lsl 32
  add.2d v2, v2, v11
  movk x13, #11030, lsl 48
  mov x15, #3072
  movk x15, #8058, lsl 16
  mov x16, #13689
  movk x15, #46097, lsl 32
  movk x16, #8159, lsl 16
  movk x15, #17047, lsl 48
  dup.2d v9, x15
  movk x16, #215, lsl 32
  mov.16b v10, v5
  movk x16, #4913, lsl 48
  fmla.2d v10, v4, v9
  mul x15, x9, x10
  fsub.2d v11, v6, v10
  fmla.2d v11, v4, v9
  umulh x9, x9, x10
  add.2d v3, v3, v10
  adds x12, x15, x12
  cinc x9, x9, hs
  add.2d v4, v7, v11
  mov x15, #65535
  mul x17, x14, x10
  movk x15, #61439, lsl 16
  umulh x14, x14, x10
  movk x15, #62867, lsl 32
  adds x9, x17, x9
  cinc x14, x14, hs
  movk x15, #1, lsl 48
  umov x17, v8.d[0]
  adds x4, x9, x4
  cinc x9, x14, hs
  umov x14, v8.d[1]
  mul x20, x13, x10
  mul x17, x17, x15
  mul x14, x14, x15
  umulh x13, x13, x10
  and x15, x17, x8
  adds x9, x20, x9
  cinc x13, x13, hs
  and x8, x14, x8
  ins v7.d[0], x15
  ins v7.d[1], x8
  adds x5, x9, x5
  cinc x8, x13, hs
  ucvtf.2d v7, v7
  mul x9, x16, x10
  mov x13, #16
  umulh x10, x16, x10
  movk x13, #22847, lsl 32
  movk x13, #17151, lsl 48
  adds x8, x9, x8
  cinc x9, x10, hs
  dup.2d v9, x13
  adds x6, x8, x6
  cinc x8, x9, hs
  mov.16b v10, v5
  fmla.2d v10, v7, v9
  add x7, x7, x8
  fsub.2d v11, v6, v10
  mov x8, #61005
  fmla.2d v11, v7, v9
  movk x8, #58262, lsl 16
  add.2d v0, v0, v10
  add.2d v8, v8, v11
  movk x8, #32851, lsl 32
  mov x9, #20728
  movk x8, #11582, lsl 48
  movk x9, #23588, lsl 16
  movk x9, #7790, lsl 32
  mov x10, #37581
  movk x9, #17170, lsl 48
  movk x10, #43836, lsl 16
  dup.2d v9, x9
  mov.16b v10, v5
  movk x10, #36286, lsl 32
  fmla.2d v10, v7, v9
  movk x10, #51783, lsl 48
  fsub.2d v11, v6, v10
  mov x9, #10899
  fmla.2d v11, v7, v9
  add.2d v1, v1, v10
  movk x9, #30709, lsl 16
  add.2d v0, v0, v11
  movk x9, #61551, lsl 32
  mov x13, #16000
  movk x13, #53891, lsl 16
  movk x9, #45784, lsl 48
  movk x13, #5509, lsl 32
  mov x14, #36612
  movk x13, #17144, lsl 48
  dup.2d v9, x13
  movk x14, #63402, lsl 16
  mov.16b v10, v5
  movk x14, #47623, lsl 32
  fmla.2d v10, v7, v9
  movk x14, #9430, lsl 48
  fsub.2d v11, v6, v10
  fmla.2d v11, v7, v9
  mul x13, x8, x11
  add.2d v2, v2, v10
  umulh x8, x8, x11
  add.2d v1, v1, v11
  mov x15, #46800
  adds x12, x13, x12
  cinc x8, x8, hs
  movk x15, #2568, lsl 16
  mul x13, x10, x11
  movk x15, #1335, lsl 32
  umulh x10, x10, x11
  movk x15, #17188, lsl 48
  dup.2d v9, x15
  adds x8, x13, x8
  cinc x10, x10, hs
  mov.16b v10, v5
  adds x4, x8, x4
  cinc x8, x10, hs
  fmla.2d v10, v7, v9
  fsub.2d v11, v6, v10
  mul x10, x9, x11
  fmla.2d v11, v7, v9
  umulh x9, x9, x11
  add.2d v4, v4, v10
  add.2d v2, v2, v11
  adds x8, x10, x8
  cinc x9, x9, hs
  mov x10, #39040
  adds x5, x8, x5
  cinc x8, x9, hs
  movk x10, #14704, lsl 16
  mul x9, x14, x11
  movk x10, #12839, lsl 32
  movk x10, #17096, lsl 48
  umulh x11, x14, x11
  dup.2d v9, x10
  adds x8, x9, x8
  cinc x9, x11, hs
  mov.16b v5, v5
  fmla.2d v5, v7, v9
  adds x6, x8, x6
  cinc x8, x9, hs
  fsub.2d v6, v6, v5
  add x7, x7, x8
  fmla.2d v6, v7, v9
  mov x8, #65535
  add.2d v3, v3, v5
  add.2d v4, v4, v6
  movk x8, #61439, lsl 16
  mov x9, #140737488355328
  movk x8, #62867, lsl 32
  dup.2d v5, x9
  and.16b v5, v3, v5
  movk x8, #49889, lsl 48
  cmeq.2d v5, v5, #0
  mul x8, x8, x12
  mov x9, #2
  movk x9, #57344, lsl 16
  mov x10, #1
  movk x9, #60199, lsl 32
  movk x10, #61440, lsl 16
  movk x9, #3, lsl 48
  movk x10, #62867, lsl 32
  dup.2d v6, x9
  bic.16b v6, v6, v5
  movk x10, #17377, lsl 48
  mov x9, #10364
  mov x11, #28817
  movk x9, #11794, lsl 16
  movk x9, #3895, lsl 32
  movk x11, #31161, lsl 16
  movk x9, #9, lsl 48
  movk x11, #59464, lsl 32
  dup.2d v7, x9
  movk x11, #10291, lsl 48
  bic.16b v7, v7, v5
  mov x9, #26576
  mov x13, #22621
  movk x9, #47696, lsl 16
  movk x13, #33153, lsl 16
  movk x9, #688, lsl 32
  movk x9, #3, lsl 48
  movk x13, #17846, lsl 32
  dup.2d v9, x9
  movk x13, #47184, lsl 48
  bic.16b v9, v9, v5
  mov x9, #46800
  mov x14, #41001
  movk x9, #2568, lsl 16
  movk x14, #57649, lsl 16
  movk x9, #1335, lsl 32
  movk x14, #20082, lsl 32
  movk x9, #4, lsl 48
  dup.2d v10, x9
  movk x14, #12388, lsl 48
  bic.16b v10, v10, v5
  mul x9, x10, x8
  mov x15, #49763
  movk x15, #40165, lsl 16
  umulh x10, x10, x8
  movk x15, #24776, lsl 32
  cmn x9, x12
  cinc x10, x10, hs
  dup.2d v11, x15
  mul x9, x11, x8
  bic.16b v5, v11, v5
  sub.2d v0, v0, v6
  umulh x11, x11, x8
  ssra.2d v0, v8, #52
  adds x9, x9, x10
  cinc x10, x11, hs
  sub.2d v6, v1, v7
  ssra.2d v6, v0, #52
  adds x4, x9, x4
  cinc x9, x10, hs
  sub.2d v7, v2, v9
  mul x10, x13, x8
  ssra.2d v7, v6, #52
  sub.2d v4, v4, v10
  umulh x11, x13, x8
  ssra.2d v4, v7, #52
  adds x9, x10, x9
  cinc x10, x11, hs
  sub.2d v5, v3, v5
  adds x5, x9, x5
  cinc x9, x10, hs
  ssra.2d v5, v4, #52
  ushr.2d v1, v6, #12
  mul x10, x14, x8
  ushr.2d v2, v7, #24
  umulh x8, x14, x8
  ushr.2d v3, v4, #36
  sli.2d v0, v6, #52
  adds x9, x10, x9
  cinc x8, x8, hs
  sli.2d v1, v7, #40
  adds x6, x9, x6
  cinc x8, x8, hs
  sli.2d v2, v4, #28
  sli.2d v3, v5, #16
  add x7, x7, x8
