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
  usra.2d v7, v0, #50
  umulh x0, x0, x3
  usra.2d v8, v1, #38
  adds x16, x17, x16
  cinc x20, x0, hs
  usra.2d v9, v2, #26
  adds x10, x12, x10
  cinc x12, x13, hs
  and.16b v0, v10, v4
  and.16b v1, v7, v4
  mul x13, x1, x1
  and.16b v2, v8, v4
  umulh x21, x1, x1
  and.16b v7, v9, v4
  adds x12, x13, x12
  cinc x13, x21, hs
  mov x21, #13605374474286268416
  adds x12, x12, x14
  cinc x13, x13, hs
  dup.2d v8, x21
  mov x14, #6440147467139809280
  mul x21, x1, x2
  dup.2d v9, x14
  umulh x14, x1, x2
  mov x22, #3688448094816436224
  adds x13, x21, x13
  cinc x23, x14, hs
  dup.2d v10, x22
  mov x22, #9209861237972664320
  adds x13, x13, x16
  cinc x16, x23, hs
  dup.2d v11, x22
  mul x22, x1, x3
  mov x23, #12218265789056155648
  umulh x1, x1, x3
  dup.2d v12, x23
  mov x23, #17739678932212383744
  adds x16, x22, x16
  cinc x24, x1, hs
  dup.2d v13, x23
  adds x16, x16, x20
  cinc x20, x24, hs
  mov x23, #2301339409586323456
  adds x11, x11, x12
  cinc x12, x15, hs
  dup.2d v14, x23
  mov x15, #7822752552742551552
  adds x12, x21, x12
  cinc x14, x14, hs
  dup.2d v15, x15
  adds x12, x12, x13
  cinc x13, x14, hs
  mov x14, #5071053180419178496
  mul x15, x2, x2
  dup.2d v16, x14
  mov x14, #16352570246982270976
  umulh x21, x2, x2
  dup.2d v17, x14
  adds x13, x15, x13
  cinc x14, x21, hs
  ucvtf.2d v0, v0
  adds x13, x13, x16
  cinc x14, x14, hs
  ucvtf.2d v1, v1
  mul x15, x2, x3
  ucvtf.2d v2, v2
  ucvtf.2d v7, v7
  umulh x2, x2, x3
  ucvtf.2d v3, v3
  adds x14, x15, x14
  cinc x16, x2, hs
  mov.16b v18, v5
  adds x14, x14, x20
  cinc x16, x16, hs
  fmla.2d v18, v0, v0
  fsub.2d v19, v6, v18
  adds x12, x17, x12
  cinc x0, x0, hs
  fmla.2d v19, v0, v0
  adds x0, x22, x0
  cinc x1, x1, hs
  add.2d v10, v10, v18
  adds x0, x0, x13
  cinc x1, x1, hs
  add.2d v8, v8, v19
  mov.16b v18, v5
  adds x1, x15, x1
  cinc x2, x2, hs
  fmla.2d v18, v0, v1
  adds x1, x1, x14
  cinc x2, x2, hs
  fsub.2d v19, v6, v18
  mul x13, x3, x3
  fmla.2d v19, v0, v1
  add.2d v18, v18, v18
  umulh x3, x3, x3
  add.2d v19, v19, v19
  adds x2, x13, x2
  cinc x3, x3, hs
  add.2d v12, v12, v18
  adds x2, x2, x16
  cinc x3, x3, hs
  add.2d v10, v10, v19
  mov x13, #48718
  mov.16b v18, v5
  fmla.2d v18, v0, v2
  movk x13, #4732, lsl 16
  fsub.2d v19, v6, v18
  movk x13, #45078, lsl 32
  fmla.2d v19, v0, v2
  movk x13, #39852, lsl 48
  add.2d v18, v18, v18
  add.2d v19, v19, v19
  mov x14, #16676
  add.2d v14, v14, v18
  movk x14, #12692, lsl 16
  add.2d v12, v12, v19
  movk x14, #20986, lsl 32
  mov.16b v18, v5
  fmla.2d v18, v0, v7
  movk x14, #2848, lsl 48
  fsub.2d v19, v6, v18
  mov x15, #51052
  fmla.2d v19, v0, v7
  movk x15, #24721, lsl 16
  add.2d v18, v18, v18
  add.2d v19, v19, v19
  movk x15, #61092, lsl 32
  add.2d v16, v16, v18
  movk x15, #45156, lsl 48
  add.2d v14, v14, v19
  mov x16, #3197
  mov.16b v18, v5
  fmla.2d v18, v0, v3
  movk x16, #18936, lsl 16
  fsub.2d v19, v6, v18
  movk x16, #10922, lsl 32
  fmla.2d v19, v0, v3
  movk x16, #11014, lsl 48
  add.2d v0, v18, v18
  mul x17, x13, x9
  add.2d v18, v19, v19
  add.2d v0, v17, v0
  umulh x13, x13, x9
  add.2d v16, v16, v18
  adds x12, x17, x12
  cinc x13, x13, hs
  mov.16b v17, v5
  mul x17, x14, x9
  fmla.2d v17, v1, v1
  fsub.2d v18, v6, v17
  umulh x14, x14, x9
  fmla.2d v18, v1, v1
  adds x13, x17, x13
  cinc x14, x14, hs
  add.2d v14, v14, v17
  adds x0, x13, x0
  cinc x13, x14, hs
  add.2d v12, v12, v18
  mov.16b v17, v5
  mul x14, x15, x9
  fmla.2d v17, v1, v2
  umulh x15, x15, x9
  fsub.2d v18, v6, v17
  adds x13, x14, x13
  cinc x14, x15, hs
  fmla.2d v18, v1, v2
  add.2d v17, v17, v17
  adds x1, x13, x1
  cinc x13, x14, hs
  add.2d v18, v18, v18
  mul x14, x16, x9
  add.2d v16, v16, v17
  umulh x9, x16, x9
  add.2d v14, v14, v18
  adds x13, x14, x13
  cinc x9, x9, hs
  mov.16b v17, v5
  fmla.2d v17, v1, v7
  adds x2, x13, x2
  cinc x9, x9, hs
  fsub.2d v18, v6, v17
  add x3, x3, x9
  fmla.2d v18, v1, v7
  mov x9, #56431
  add.2d v17, v17, v17
  add.2d v18, v18, v18
  movk x9, #30457, lsl 16
  add.2d v0, v0, v17
  movk x9, #30012, lsl 32
  add.2d v16, v16, v18
  movk x9, #6382, lsl 48
  mov.16b v17, v5
  fmla.2d v17, v1, v3
  mov x13, #59151
  fsub.2d v18, v6, v17
  movk x13, #41769, lsl 16
  fmla.2d v18, v1, v3
  movk x13, #32276, lsl 32
  add.2d v1, v17, v17
  add.2d v17, v18, v18
  movk x13, #21677, lsl 48
  add.2d v1, v15, v1
  mov x14, #34015
  add.2d v0, v0, v17
  movk x14, #20342, lsl 16
  mov.16b v15, v5
  fmla.2d v15, v2, v2
  movk x14, #13935, lsl 32
  fsub.2d v17, v6, v15
  movk x14, #11030, lsl 48
  fmla.2d v17, v2, v2
  mov x15, #13689
  add.2d v0, v0, v15
  movk x15, #8159, lsl 16
  add.2d v15, v16, v17
  mov.16b v16, v5
  movk x15, #215, lsl 32
  fmla.2d v16, v2, v7
  movk x15, #4913, lsl 48
  fsub.2d v17, v6, v16
  mul x16, x9, x10
  fmla.2d v17, v2, v7
  add.2d v16, v16, v16
  umulh x9, x9, x10
  add.2d v17, v17, v17
  adds x12, x16, x12
  cinc x9, x9, hs
  add.2d v1, v1, v16
  mul x16, x13, x10
  add.2d v0, v0, v17
  mov.16b v16, v5
  umulh x13, x13, x10
  fmla.2d v16, v2, v3
  adds x9, x16, x9
  cinc x13, x13, hs
  fsub.2d v17, v6, v16
  adds x0, x9, x0
  cinc x9, x13, hs
  fmla.2d v17, v2, v3
  add.2d v2, v16, v16
  mul x13, x14, x10
  add.2d v16, v17, v17
  umulh x14, x14, x10
  add.2d v2, v13, v2
  adds x9, x13, x9
  cinc x13, x14, hs
  add.2d v1, v1, v16
  mov.16b v13, v5
  adds x1, x9, x1
  cinc x9, x13, hs
  fmla.2d v13, v7, v7
  mul x13, x15, x10
  fsub.2d v16, v6, v13
  umulh x10, x15, x10
  fmla.2d v16, v7, v7
  adds x9, x13, x9
  cinc x10, x10, hs
  add.2d v2, v2, v13
  add.2d v1, v1, v16
  adds x2, x9, x2
  cinc x9, x10, hs
  mov.16b v13, v5
  add x3, x3, x9
  fmla.2d v13, v7, v3
  mov x9, #61005
  fsub.2d v16, v6, v13
  fmla.2d v16, v7, v3
  movk x9, #58262, lsl 16
  add.2d v7, v13, v13
  movk x9, #32851, lsl 32
  add.2d v13, v16, v16
  movk x9, #11582, lsl 48
  add.2d v7, v11, v7
  add.2d v2, v2, v13
  mov x10, #37581
  mov.16b v11, v5
  movk x10, #43836, lsl 16
  fmla.2d v11, v3, v3
  movk x10, #36286, lsl 32
  fsub.2d v13, v6, v11
  fmla.2d v13, v3, v3
  movk x10, #51783, lsl 48
  add.2d v3, v9, v11
  mov x13, #10899
  add.2d v7, v7, v13
  movk x13, #30709, lsl 16
  usra.2d v10, v8, #52
  movk x13, #61551, lsl 32
  usra.2d v12, v10, #52
  usra.2d v14, v12, #52
  movk x13, #45784, lsl 48
  usra.2d v15, v14, #52
  mov x14, #36612
  and.16b v8, v8, v4
  movk x14, #63402, lsl 16
  and.16b v9, v10, v4
  and.16b v10, v12, v4
  movk x14, #47623, lsl 32
  and.16b v4, v14, v4
  movk x14, #9430, lsl 48
  ucvtf.2d v8, v8
  mul x15, x9, x11
  mov x16, #37864
  movk x16, #1815, lsl 16
  umulh x9, x9, x11
  movk x16, #28960, lsl 32
  adds x12, x15, x12
  cinc x9, x9, hs
  movk x16, #17153, lsl 48
  mul x15, x10, x11
  dup.2d v11, x16
  mov.16b v12, v5
  umulh x10, x10, x11
  fmla.2d v12, v8, v11
  adds x9, x15, x9
  cinc x10, x10, hs
  fsub.2d v13, v6, v12
  adds x0, x9, x0
  cinc x9, x10, hs
  fmla.2d v13, v8, v11
  add.2d v0, v0, v12
  mul x10, x13, x11
  add.2d v11, v15, v13
  umulh x13, x13, x11
  mov x15, #46128
  adds x9, x10, x9
  cinc x10, x13, hs
  movk x15, #29964, lsl 16
  adds x1, x9, x1
  cinc x9, x10, hs
  movk x15, #7587, lsl 32
  movk x15, #17161, lsl 48
  mul x10, x14, x11
  dup.2d v12, x15
  umulh x11, x14, x11
  mov.16b v13, v5
  adds x9, x10, x9
  cinc x10, x11, hs
  fmla.2d v13, v8, v12
  fsub.2d v14, v6, v13
  adds x2, x9, x2
  cinc x9, x10, hs
  fmla.2d v14, v8, v12
  add x3, x3, x9
  add.2d v1, v1, v13
  mov x9, #65535
  add.2d v0, v0, v14
  mov x10, #52826
  movk x9, #61439, lsl 16
  movk x10, #57790, lsl 16
  movk x9, #62867, lsl 32
  movk x10, #55431, lsl 32
  movk x9, #49889, lsl 48
  movk x10, #17196, lsl 48
  dup.2d v12, x10
  mul x9, x9, x12
  mov.16b v13, v5
  mov x10, #1
  fmla.2d v13, v8, v12
  movk x10, #61440, lsl 16
  fsub.2d v14, v6, v13
  movk x10, #62867, lsl 32
  fmla.2d v14, v8, v12
  add.2d v2, v2, v13
  movk x10, #17377, lsl 48
  add.2d v1, v1, v14
  mov x11, #28817
  mov x13, #31276
  movk x11, #31161, lsl 16
  movk x13, #21262, lsl 16
  movk x13, #2304, lsl 32
  movk x11, #59464, lsl 32
  movk x13, #17182, lsl 48
  movk x11, #10291, lsl 48
  dup.2d v12, x13
  mov x13, #22621
  mov.16b v13, v5
  fmla.2d v13, v8, v12
  movk x13, #33153, lsl 16
  fsub.2d v14, v6, v13
  movk x13, #17846, lsl 32
  fmla.2d v14, v8, v12
  movk x13, #47184, lsl 48
  add.2d v7, v7, v13
  add.2d v2, v2, v14
  mov x14, #41001
  mov x15, #28672
  movk x14, #57649, lsl 16
  movk x15, #24515, lsl 16
  movk x14, #20082, lsl 32
  movk x15, #54929, lsl 32
  movk x15, #17064, lsl 48
  movk x14, #12388, lsl 48
  dup.2d v12, x15
  mul x15, x10, x9
  mov.16b v13, v5
  umulh x10, x10, x9
  fmla.2d v13, v8, v12
  cmn x15, x12
  cinc x10, x10, hs
  fsub.2d v14, v6, v13
  fmla.2d v14, v8, v12
  mul x12, x11, x9
  add.2d v3, v3, v13
  umulh x11, x11, x9
  add.2d v7, v7, v14
  adds x10, x12, x10
  cinc x11, x11, hs
  ucvtf.2d v8, v9
  mov x12, #44768
  adds x0, x10, x0
  cinc x10, x11, hs
  movk x12, #51919, lsl 16
  mul x11, x13, x9
  movk x12, #6346, lsl 32
  umulh x13, x13, x9
  movk x12, #17133, lsl 48
  dup.2d v9, x12
  adds x10, x11, x10
  cinc x11, x13, hs
  mov.16b v12, v5
  adds x1, x10, x1
  cinc x10, x11, hs
  fmla.2d v12, v8, v9
  mul x11, x14, x9
  fsub.2d v13, v6, v12
  fmla.2d v13, v8, v9
  umulh x9, x14, x9
  add.2d v0, v0, v12
  adds x10, x11, x10
  cinc x9, x9, hs
  add.2d v9, v11, v13
  adds x2, x10, x2
  cinc x9, x9, hs
  mov x10, #47492
  movk x10, #23630, lsl 16
  add x3, x3, x9
  movk x10, #49985, lsl 32
  mul x9, x4, x4
  movk x10, #17168, lsl 48
  umulh x11, x4, x4
  dup.2d v11, x10
  mul x10, x4, x5
  mov.16b v12, v5
  fmla.2d v12, v8, v11
  umulh x12, x4, x5
  fsub.2d v13, v6, v12
  adds x11, x10, x11
  cinc x13, x12, hs
  fmla.2d v13, v8, v11
  mul x14, x4, x6
  add.2d v1, v1, v12
  add.2d v0, v0, v13
  umulh x15, x4, x6
  mov x16, #57936
  adds x13, x14, x13
  cinc x17, x15, hs
  movk x16, #54828, lsl 16
  mul x20, x4, x7
  movk x16, #18292, lsl 32
  movk x16, #17197, lsl 48
  umulh x4, x4, x7
  dup.2d v11, x16
  adds x16, x20, x17
  cinc x17, x4, hs
  mov.16b v12, v5
  adds x10, x10, x11
  cinc x11, x12, hs
  fmla.2d v12, v8, v11
  fsub.2d v13, v6, v12
  mul x12, x5, x5
  fmla.2d v13, v8, v11
  umulh x21, x5, x5
  add.2d v2, v2, v12
  adds x11, x12, x11
  cinc x12, x21, hs
  add.2d v1, v1, v13
  adds x11, x11, x13
  cinc x12, x12, hs
  mov x13, #17708
  movk x13, #43915, lsl 16
  mul x21, x5, x6
  movk x13, #64348, lsl 32
  umulh x22, x5, x6
  movk x13, #17188, lsl 48
  adds x12, x21, x12
  cinc x23, x22, hs
  dup.2d v11, x13
  mov.16b v12, v5
  adds x12, x12, x16
  cinc x13, x23, hs
  fmla.2d v12, v8, v11
  mul x16, x5, x7
  fsub.2d v13, v6, v12
  umulh x5, x5, x7
  fmla.2d v13, v8, v11
  add.2d v7, v7, v12
  adds x13, x16, x13
  cinc x23, x5, hs
  add.2d v2, v2, v13
  adds x13, x13, x17
  cinc x17, x23, hs
  mov x23, #29184
  adds x11, x14, x11
  cinc x14, x15, hs
  movk x23, #20789, lsl 16
  movk x23, #19197, lsl 32
  adds x14, x21, x14
  cinc x15, x22, hs
  movk x23, #17083, lsl 48
  adds x12, x14, x12
  cinc x14, x15, hs
  dup.2d v11, x23
  mul x15, x6, x6
  mov.16b v12, v5
  fmla.2d v12, v8, v11
  umulh x21, x6, x6
  fsub.2d v13, v6, v12
  adds x14, x15, x14
  cinc x15, x21, hs
  fmla.2d v13, v8, v11
  adds x13, x14, x13
  cinc x14, x15, hs
  add.2d v3, v3, v12
  mul x15, x6, x7
  add.2d v7, v7, v13
  ucvtf.2d v8, v10
  umulh x6, x6, x7
  mov x21, #58856
  adds x14, x15, x14
  cinc x22, x6, hs
  movk x21, #14953, lsl 16
  adds x14, x14, x17
  cinc x17, x22, hs
  movk x21, #15155, lsl 32
  movk x21, #17181, lsl 48
  adds x12, x20, x12
  cinc x4, x4, hs
  dup.2d v10, x21
  adds x4, x16, x4
  cinc x5, x5, hs
  mov.16b v11, v5
  adds x4, x4, x13
  cinc x5, x5, hs
  fmla.2d v11, v8, v10
  fsub.2d v12, v6, v11
  adds x5, x15, x5
  cinc x6, x6, hs
  fmla.2d v12, v8, v10
  adds x5, x5, x14
  cinc x6, x6, hs
  add.2d v0, v0, v11
  mul x13, x7, x7
  add.2d v9, v9, v12
  mov x14, #35392
  umulh x7, x7, x7
  movk x14, #12477, lsl 16
  adds x6, x13, x6
  cinc x7, x7, hs
  movk x14, #56780, lsl 32
  adds x6, x6, x17
  cinc x7, x7, hs
  movk x14, #17142, lsl 48
  mov x13, #48718
  dup.2d v10, x14
  mov.16b v11, v5
  movk x13, #4732, lsl 16
  fmla.2d v11, v8, v10
  movk x13, #45078, lsl 32
  fsub.2d v12, v6, v11
  movk x13, #39852, lsl 48
  fmla.2d v12, v8, v10
  add.2d v1, v1, v11
  mov x14, #16676
  add.2d v0, v0, v12
  movk x14, #12692, lsl 16
  mov x15, #9848
  movk x14, #20986, lsl 32
  movk x15, #54501, lsl 16
  movk x15, #31540, lsl 32
  movk x14, #2848, lsl 48
  movk x15, #17170, lsl 48
  mov x16, #51052
  dup.2d v10, x15
  movk x16, #24721, lsl 16
  mov.16b v11, v5
  fmla.2d v11, v8, v10
  movk x16, #61092, lsl 32
  fsub.2d v12, v6, v11
  movk x16, #45156, lsl 48
  fmla.2d v12, v8, v10
  mov x15, #3197
  add.2d v2, v2, v11
  add.2d v1, v1, v12
  movk x15, #18936, lsl 16
  mov x17, #9584
  movk x15, #10922, lsl 32
  movk x17, #63883, lsl 16
  movk x15, #11014, lsl 48
  movk x17, #18253, lsl 32
  mul x20, x13, x9
  movk x17, #17190, lsl 48
  dup.2d v10, x17
  umulh x13, x13, x9
  mov.16b v11, v5
  adds x12, x20, x12
  cinc x13, x13, hs
  fmla.2d v11, v8, v10
  mul x17, x14, x9
  fsub.2d v12, v6, v11
  fmla.2d v12, v8, v10
  umulh x14, x14, x9
  add.2d v7, v7, v11
  adds x13, x17, x13
  cinc x14, x14, hs
  add.2d v2, v2, v12
  adds x4, x13, x4
  cinc x13, x14, hs
  mov x14, #51712
  movk x14, #16093, lsl 16
  mul x17, x16, x9
  movk x14, #30633, lsl 32
  umulh x16, x16, x9
  movk x14, #17068, lsl 48
  adds x13, x17, x13
  cinc x16, x16, hs
  dup.2d v10, x14
  mov.16b v11, v5
  adds x5, x13, x5
  cinc x13, x16, hs
  fmla.2d v11, v8, v10
  mul x14, x15, x9
  fsub.2d v12, v6, v11
  umulh x9, x15, x9
  fmla.2d v12, v8, v10
  adds x13, x14, x13
  cinc x9, x9, hs
  add.2d v3, v3, v11
  add.2d v7, v7, v12
  adds x6, x13, x6
  cinc x9, x9, hs
  ucvtf.2d v4, v4
  add x7, x7, x9
  mov x9, #34724
  mov x13, #56431
  movk x9, #40393, lsl 16
  movk x9, #23752, lsl 32
  movk x13, #30457, lsl 16
  movk x9, #17184, lsl 48
  movk x13, #30012, lsl 32
  dup.2d v8, x9
  movk x13, #6382, lsl 48
  mov.16b v10, v5
  fmla.2d v10, v4, v8
  mov x9, #59151
  fsub.2d v11, v6, v10
  movk x9, #41769, lsl 16
  fmla.2d v11, v4, v8
  movk x9, #32276, lsl 32
  add.2d v0, v0, v10
  add.2d v8, v9, v11
  movk x9, #21677, lsl 48
  mov x14, #25532
  mov x15, #34015
  movk x14, #31025, lsl 16
  movk x15, #20342, lsl 16
  movk x14, #10002, lsl 32
  movk x14, #17199, lsl 48
  movk x15, #13935, lsl 32
  dup.2d v9, x14
  movk x15, #11030, lsl 48
  mov.16b v10, v5
  mov x14, #13689
  fmla.2d v10, v4, v9
  movk x14, #8159, lsl 16
  fsub.2d v11, v6, v10
  fmla.2d v11, v4, v9
  movk x14, #215, lsl 32
  add.2d v1, v1, v10
  movk x14, #4913, lsl 48
  add.2d v0, v0, v11
  mul x16, x13, x10
  mov x17, #18830
  movk x17, #2465, lsl 16
  umulh x13, x13, x10
  movk x17, #36348, lsl 32
  adds x12, x16, x12
  cinc x13, x13, hs
  movk x17, #17194, lsl 48
  mul x16, x9, x10
  dup.2d v9, x17
  mov.16b v10, v5
  umulh x9, x9, x10
  fmla.2d v10, v4, v9
  adds x13, x16, x13
  cinc x9, x9, hs
  fsub.2d v11, v6, v10
  adds x4, x13, x4
  cinc x9, x9, hs
  fmla.2d v11, v4, v9
  add.2d v2, v2, v10
  mul x13, x15, x10
  add.2d v1, v1, v11
  umulh x15, x15, x10
  mov x16, #21566
  adds x9, x13, x9
  cinc x13, x15, hs
  movk x16, #43708, lsl 16
  movk x16, #57685, lsl 32
  adds x5, x9, x5
  cinc x9, x13, hs
  movk x16, #17185, lsl 48
  mul x13, x14, x10
  dup.2d v9, x16
  umulh x10, x14, x10
  mov.16b v10, v5
  adds x9, x13, x9
  cinc x10, x10, hs
  fmla.2d v10, v4, v9
  fsub.2d v11, v6, v10
  adds x6, x9, x6
  cinc x9, x10, hs
  fmla.2d v11, v4, v9
  add x7, x7, x9
  add.2d v7, v7, v10
  mov x9, #61005
  add.2d v2, v2, v11
  mov x10, #3072
  movk x9, #58262, lsl 16
  movk x10, #8058, lsl 16
  movk x9, #32851, lsl 32
  movk x10, #46097, lsl 32
  movk x9, #11582, lsl 48
  movk x10, #17047, lsl 48
  dup.2d v9, x10
  mov x10, #37581
  mov.16b v10, v5
  movk x10, #43836, lsl 16
  fmla.2d v10, v4, v9
  movk x10, #36286, lsl 32
  fsub.2d v11, v6, v10
  fmla.2d v11, v4, v9
  movk x10, #51783, lsl 48
  add.2d v3, v3, v10
  mov x13, #10899
  add.2d v4, v7, v11
  movk x13, #30709, lsl 16
  mov x14, #65535
  movk x13, #61551, lsl 32
  movk x14, #61439, lsl 16
  movk x14, #62867, lsl 32
  movk x13, #45784, lsl 48
  movk x14, #1, lsl 48
  mov x15, #36612
  umov x16, v8.d[0]
  movk x15, #63402, lsl 16
  umov x17, v8.d[1]
  mul x16, x16, x14
  movk x15, #47623, lsl 32
  mul x14, x17, x14
  movk x15, #9430, lsl 48
  and x16, x16, x8
  mul x17, x9, x11
  and x8, x14, x8
  ins v7.d[0], x16
  ins v7.d[1], x8
  umulh x8, x9, x11
  ucvtf.2d v7, v7
  adds x9, x17, x12
  cinc x8, x8, hs
  mov x12, #16
  mul x14, x10, x11
  movk x12, #22847, lsl 32
  movk x12, #17151, lsl 48
  umulh x10, x10, x11
  dup.2d v9, x12
  adds x8, x14, x8
  cinc x10, x10, hs
  mov.16b v10, v5
  adds x4, x8, x4
  cinc x8, x10, hs
  fmla.2d v10, v7, v9
  fsub.2d v11, v6, v10
  mul x10, x13, x11
  fmla.2d v11, v7, v9
  umulh x12, x13, x11
  add.2d v0, v0, v10
  adds x8, x10, x8
  cinc x10, x12, hs
  add.2d v8, v8, v11
  adds x5, x8, x5
  cinc x8, x10, hs
  mov x10, #20728
  movk x10, #23588, lsl 16
  mul x12, x15, x11
  movk x10, #7790, lsl 32
  umulh x11, x15, x11
  movk x10, #17170, lsl 48
  adds x8, x12, x8
  cinc x11, x11, hs
  dup.2d v9, x10
  mov.16b v10, v5
  adds x6, x8, x6
  cinc x8, x11, hs
  fmla.2d v10, v7, v9
  add x7, x7, x8
  fsub.2d v11, v6, v10
  mov x8, #65535
  fmla.2d v11, v7, v9
  add.2d v1, v1, v10
  movk x8, #61439, lsl 16
  add.2d v0, v0, v11
  movk x8, #62867, lsl 32
  mov x10, #16000
  movk x8, #49889, lsl 48
  movk x10, #53891, lsl 16
  movk x10, #5509, lsl 32
  mul x8, x8, x9
  movk x10, #17144, lsl 48
  mov x11, #1
  dup.2d v9, x10
  movk x11, #61440, lsl 16
  mov.16b v10, v5
  movk x11, #62867, lsl 32
  fmla.2d v10, v7, v9
  fsub.2d v11, v6, v10
  movk x11, #17377, lsl 48
  fmla.2d v11, v7, v9
  mov x10, #28817
  add.2d v2, v2, v10
  movk x10, #31161, lsl 16
  add.2d v9, v1, v11
  mov x12, #46800
  movk x10, #59464, lsl 32
  movk x12, #2568, lsl 16
  movk x10, #10291, lsl 48
  movk x12, #1335, lsl 32
  mov x13, #22621
  movk x12, #17188, lsl 48
  dup.2d v1, x12
  movk x13, #33153, lsl 16
  mov.16b v10, v5
  movk x13, #17846, lsl 32
  fmla.2d v10, v7, v1
  movk x13, #47184, lsl 48
  fsub.2d v11, v6, v10
  fmla.2d v11, v7, v1
  mov x12, #41001
  add.2d v1, v4, v10
  movk x12, #57649, lsl 16
  add.2d v4, v2, v11
  movk x12, #20082, lsl 32
  mov x14, #39040
  movk x14, #14704, lsl 16
  movk x12, #12388, lsl 48
  movk x14, #12839, lsl 32
  mul x15, x11, x8
  movk x14, #17096, lsl 48
  umulh x11, x11, x8
  dup.2d v2, x14
  cmn x15, x9
  cinc x11, x11, hs
  mov.16b v5, v5
  fmla.2d v5, v7, v2
  mul x9, x10, x8
  fsub.2d v6, v6, v5
  umulh x10, x10, x8
  fmla.2d v6, v7, v2
  adds x9, x9, x11
  cinc x10, x10, hs
  add.2d v5, v3, v5
  add.2d v6, v1, v6
  adds x4, x9, x4
  cinc x9, x10, hs
  ssra.2d v0, v8, #52
  mul x10, x13, x8
  ssra.2d v9, v0, #52
  umulh x11, x13, x8
  ssra.2d v4, v9, #52
  ssra.2d v6, v4, #52
  adds x9, x10, x9
  cinc x10, x11, hs
  ssra.2d v5, v6, #52
  adds x5, x9, x5
  cinc x9, x10, hs
  ushr.2d v1, v9, #12
  mul x10, x12, x8
  ushr.2d v2, v4, #24
  ushr.2d v3, v6, #36
  umulh x8, x12, x8
  sli.2d v0, v9, #52
  adds x9, x10, x9
  cinc x8, x8, hs
  sli.2d v1, v4, #40
  adds x6, x9, x6
  cinc x8, x8, hs
  sli.2d v2, v6, #28
  sli.2d v3, v5, #16
  add x7, x7, x8
