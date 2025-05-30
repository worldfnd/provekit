// GENERATED FILE, DO NOT EDIT!
// in("x0") a[0], in("x1") a[1], in("x2") a[2], in("x3") a[3],
// in("x4") b[0], in("x5") b[1], in("x6") b[2], in("x7") b[3],
// in("x8") a1[0], in("x9") a1[1], in("x10") a1[2], in("x11") a1[3],
// in("x12") b1[0], in("x13") b1[1], in("x14") b1[2], in("x15") b1[3],
// in("v0") av[0], in("v1") av[1], in("v2") av[2], in("v3") av[3],
// in("v4") bv[0], in("v5") bv[1], in("v6") bv[2], in("v7") bv[3],
// lateout("x0") out[0], lateout("x1") out[1], lateout("x2") out[2], lateout("x3") out[3],
// lateout("x4") out1[0], lateout("x5") out1[1], lateout("x6") out1[2], lateout("x7") out1[3],
// lateout("v0") outv[0], lateout("v1") outv[1], lateout("v2") outv[2], lateout("v3") outv[3],
// lateout("x8") _, lateout("x9") _, lateout("x10") _, lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _, lateout("x15") _, lateout("x16") _, lateout("x17") _, lateout("x20") _, lateout("x21") _, lateout("x22") _, lateout("x23") _, lateout("x24") _, lateout("x25") _, lateout("x26") _, lateout("v4") _, lateout("v5") _, lateout("v6") _, lateout("v7") _, lateout("v8") _, lateout("v9") _, lateout("v10") _, lateout("v11") _, lateout("v12") _, lateout("v13") _, lateout("v14") _, lateout("v15") _, lateout("v16") _, lateout("v17") _, lateout("v18") _, lateout("v19") _, lateout("v20") _, lateout("v21") _, lateout("v22") _, lateout("v23") _, lateout("v24") _,
// lateout("lr") _
  mov x16, #4503599627370495
  mul x17, x0, x4
  dup.2d v8, x16
  umulh x20, x0, x4
  mov x21, #5075556780046548992
  dup.2d v9, x21
  mul x21, x1, x4
  mov x22, #1
  umulh x23, x1, x4
  movk x22, #18032, lsl 48
  adds x20, x21, x20
  cinc x21, x23, hs
  dup.2d v10, x22
  shl.2d v11, v1, #14
  mul x22, x2, x4
  shl.2d v12, v2, #26
  umulh x23, x2, x4
  shl.2d v13, v3, #38
  adds x21, x22, x21
  cinc x22, x23, hs
  ushr.2d v3, v3, #14
  shl.2d v14, v0, #2
  mul x23, x3, x4
  usra.2d v11, v0, #50
  umulh x4, x3, x4
  usra.2d v12, v1, #38
  adds x22, x23, x22
  cinc x4, x4, hs
  usra.2d v13, v2, #26
  and.16b v0, v14, v8
  mul x23, x0, x5
  and.16b v1, v11, v8
  umulh x24, x0, x5
  and.16b v2, v12, v8
  adds x20, x23, x20
  cinc x23, x24, hs
  and.16b v11, v13, v8
  shl.2d v12, v5, #14
  mul x24, x1, x5
  shl.2d v13, v6, #26
  umulh x25, x1, x5
  shl.2d v14, v7, #38
  adds x23, x24, x23
  cinc x24, x25, hs
  ushr.2d v7, v7, #14
  shl.2d v15, v4, #2
  adds x21, x23, x21
  cinc x23, x24, hs
  usra.2d v12, v4, #50
  mul x24, x2, x5
  usra.2d v13, v5, #38
  usra.2d v14, v6, #26
  umulh x25, x2, x5
  and.16b v4, v15, v8
  adds x23, x24, x23
  cinc x24, x25, hs
  and.16b v5, v12, v8
  adds x22, x23, x22
  cinc x23, x24, hs
  and.16b v6, v13, v8
  and.16b v12, v14, v8
  mul x24, x3, x5
  mov x25, #13605374474286268416
  umulh x5, x3, x5
  dup.2d v13, x25
  adds x23, x24, x23
  cinc x5, x5, hs
  mov x24, #6440147467139809280
  dup.2d v14, x24
  adds x4, x23, x4
  cinc x5, x5, hs
  mov x23, #3688448094816436224
  mul x24, x0, x6
  dup.2d v15, x23
  umulh x23, x0, x6
  mov x25, #9209861237972664320
  dup.2d v16, x25
  adds x21, x24, x21
  cinc x23, x23, hs
  mov x24, #12218265789056155648
  mul x25, x1, x6
  dup.2d v17, x24
  umulh x24, x1, x6
  mov x26, #17739678932212383744
  dup.2d v18, x26
  adds x23, x25, x23
  cinc x24, x24, hs
  mov x25, #2301339409586323456
  adds x22, x23, x22
  cinc x23, x24, hs
  dup.2d v19, x25
  mul x24, x2, x6
  mov x25, #7822752552742551552
  dup.2d v20, x25
  umulh x25, x2, x6
  mov x26, #5071053180419178496
  adds x23, x24, x23
  cinc x24, x25, hs
  dup.2d v21, x26
  adds x4, x23, x4
  cinc x23, x24, hs
  mov x24, #16352570246982270976
  dup.2d v22, x24
  mul x24, x3, x6
  ucvtf.2d v0, v0
  umulh x6, x3, x6
  ucvtf.2d v1, v1
  ucvtf.2d v2, v2
  adds x23, x24, x23
  cinc x6, x6, hs
  ucvtf.2d v11, v11
  adds x5, x23, x5
  cinc x6, x6, hs
  ucvtf.2d v3, v3
  mul x23, x0, x7
  ucvtf.2d v4, v4
  ucvtf.2d v5, v5
  umulh x0, x0, x7
  ucvtf.2d v6, v6
  adds x22, x23, x22
  cinc x0, x0, hs
  ucvtf.2d v12, v12
  mul x23, x1, x7
  ucvtf.2d v7, v7
  mov.16b v23, v9
  umulh x1, x1, x7
  fmla.2d v23, v0, v4
  adds x0, x23, x0
  cinc x1, x1, hs
  fsub.2d v24, v10, v23
  adds x0, x0, x4
  cinc x1, x1, hs
  fmla.2d v24, v0, v4
  add.2d v15, v15, v23
  mul x4, x2, x7
  add.2d v13, v13, v24
  umulh x2, x2, x7
  mov.16b v23, v9
  adds x1, x4, x1
  cinc x2, x2, hs
  fmla.2d v23, v0, v5
  fsub.2d v24, v10, v23
  adds x1, x1, x5
  cinc x2, x2, hs
  fmla.2d v24, v0, v5
  mul x4, x3, x7
  add.2d v17, v17, v23
  umulh x3, x3, x7
  add.2d v15, v15, v24
  mov.16b v23, v9
  adds x2, x4, x2
  cinc x3, x3, hs
  fmla.2d v23, v0, v6
  adds x2, x2, x6
  cinc x3, x3, hs
  fsub.2d v24, v10, v23
  mov x4, #48718
  fmla.2d v24, v0, v6
  add.2d v19, v19, v23
  movk x4, #4732, lsl 16
  add.2d v17, v17, v24
  movk x4, #45078, lsl 32
  mov.16b v23, v9
  fmla.2d v23, v0, v12
  movk x4, #39852, lsl 48
  fsub.2d v24, v10, v23
  mov x5, #16676
  fmla.2d v24, v0, v12
  movk x5, #12692, lsl 16
  add.2d v21, v21, v23
  add.2d v19, v19, v24
  movk x5, #20986, lsl 32
  mov.16b v23, v9
  movk x5, #2848, lsl 48
  fmla.2d v23, v0, v7
  mov x6, #51052
  fsub.2d v24, v10, v23
  fmla.2d v24, v0, v7
  movk x6, #24721, lsl 16
  add.2d v0, v22, v23
  movk x6, #61092, lsl 32
  add.2d v21, v21, v24
  movk x6, #45156, lsl 48
  mov.16b v22, v9
  fmla.2d v22, v1, v4
  mov x7, #3197
  fsub.2d v23, v10, v22
  movk x7, #18936, lsl 16
  fmla.2d v23, v1, v4
  movk x7, #10922, lsl 32
  add.2d v17, v17, v22
  add.2d v15, v15, v23
  movk x7, #11014, lsl 48
  mov.16b v22, v9
  mul x23, x4, x17
  fmla.2d v22, v1, v5
  umulh x4, x4, x17
  fsub.2d v23, v10, v22
  fmla.2d v23, v1, v5
  adds x22, x23, x22
  cinc x4, x4, hs
  add.2d v19, v19, v22
  mul x23, x5, x17
  add.2d v17, v17, v23
  umulh x5, x5, x17
  mov.16b v22, v9
  fmla.2d v22, v1, v6
  adds x4, x23, x4
  cinc x5, x5, hs
  fsub.2d v23, v10, v22
  adds x0, x4, x0
  cinc x4, x5, hs
  fmla.2d v23, v1, v6
  add.2d v21, v21, v22
  mul x5, x6, x17
  add.2d v19, v19, v23
  umulh x6, x6, x17
  mov.16b v22, v9
  adds x4, x5, x4
  cinc x5, x6, hs
  fmla.2d v22, v1, v12
  fsub.2d v23, v10, v22
  adds x1, x4, x1
  cinc x4, x5, hs
  fmla.2d v23, v1, v12
  mul x5, x7, x17
  add.2d v0, v0, v22
  umulh x6, x7, x17
  add.2d v21, v21, v23
  mov.16b v22, v9
  adds x4, x5, x4
  cinc x5, x6, hs
  fmla.2d v22, v1, v7
  adds x2, x4, x2
  cinc x4, x5, hs
  fsub.2d v23, v10, v22
  add x3, x3, x4
  fmla.2d v23, v1, v7
  add.2d v1, v20, v22
  mov x4, #56431
  add.2d v0, v0, v23
  movk x4, #30457, lsl 16
  mov.16b v20, v9
  movk x4, #30012, lsl 32
  fmla.2d v20, v2, v4
  fsub.2d v22, v10, v20
  movk x4, #6382, lsl 48
  fmla.2d v22, v2, v4
  mov x5, #59151
  add.2d v19, v19, v20
  movk x5, #41769, lsl 16
  add.2d v17, v17, v22
  mov.16b v20, v9
  movk x5, #32276, lsl 32
  fmla.2d v20, v2, v5
  movk x5, #21677, lsl 48
  fsub.2d v22, v10, v20
  mov x6, #34015
  fmla.2d v22, v2, v5
  add.2d v20, v21, v20
  movk x6, #20342, lsl 16
  add.2d v19, v19, v22
  movk x6, #13935, lsl 32
  mov.16b v21, v9
  fmla.2d v21, v2, v6
  movk x6, #11030, lsl 48
  fsub.2d v22, v10, v21
  mov x7, #13689
  fmla.2d v22, v2, v6
  movk x7, #8159, lsl 16
  add.2d v0, v0, v21
  add.2d v20, v20, v22
  movk x7, #215, lsl 32
  mov.16b v21, v9
  movk x7, #4913, lsl 48
  fmla.2d v21, v2, v12
  mul x17, x4, x20
  fsub.2d v22, v10, v21
  fmla.2d v22, v2, v12
  umulh x4, x4, x20
  add.2d v1, v1, v21
  adds x17, x17, x22
  cinc x4, x4, hs
  add.2d v0, v0, v22
  mul x22, x5, x20
  mov.16b v21, v9
  fmla.2d v21, v2, v7
  umulh x5, x5, x20
  fsub.2d v22, v10, v21
  adds x4, x22, x4
  cinc x5, x5, hs
  fmla.2d v22, v2, v7
  adds x0, x4, x0
  cinc x4, x5, hs
  add.2d v2, v18, v21
  add.2d v1, v1, v22
  mul x5, x6, x20
  mov.16b v18, v9
  umulh x6, x6, x20
  fmla.2d v18, v11, v4
  adds x4, x5, x4
  cinc x5, x6, hs
  fsub.2d v21, v10, v18
  fmla.2d v21, v11, v4
  adds x1, x4, x1
  cinc x4, x5, hs
  add.2d v18, v20, v18
  mul x5, x7, x20
  add.2d v19, v19, v21
  umulh x6, x7, x20
  mov.16b v20, v9
  fmla.2d v20, v11, v5
  adds x4, x5, x4
  cinc x5, x6, hs
  fsub.2d v21, v10, v20
  adds x2, x4, x2
  cinc x4, x5, hs
  fmla.2d v21, v11, v5
  add.2d v0, v0, v20
  add x3, x3, x4
  add.2d v18, v18, v21
  mov x4, #61005
  mov.16b v20, v9
  movk x4, #58262, lsl 16
  fmla.2d v20, v11, v6
  fsub.2d v21, v10, v20
  movk x4, #32851, lsl 32
  fmla.2d v21, v11, v6
  movk x4, #11582, lsl 48
  add.2d v1, v1, v20
  mov x5, #37581
  add.2d v0, v0, v21
  mov.16b v20, v9
  movk x5, #43836, lsl 16
  fmla.2d v20, v11, v12
  movk x5, #36286, lsl 32
  fsub.2d v21, v10, v20
  movk x5, #51783, lsl 48
  fmla.2d v21, v11, v12
  add.2d v2, v2, v20
  mov x6, #10899
  add.2d v1, v1, v21
  movk x6, #30709, lsl 16
  mov.16b v20, v9
  movk x6, #61551, lsl 32
  fmla.2d v20, v11, v7
  fsub.2d v21, v10, v20
  movk x6, #45784, lsl 48
  fmla.2d v21, v11, v7
  mov x7, #36612
  add.2d v11, v16, v20
  movk x7, #63402, lsl 16
  add.2d v2, v2, v21
  mov.16b v16, v9
  movk x7, #47623, lsl 32
  fmla.2d v16, v3, v4
  movk x7, #9430, lsl 48
  fsub.2d v20, v10, v16
  mul x20, x4, x21
  fmla.2d v20, v3, v4
  add.2d v0, v0, v16
  umulh x4, x4, x21
  add.2d v4, v18, v20
  adds x17, x20, x17
  cinc x4, x4, hs
  mov.16b v16, v9
  fmla.2d v16, v3, v5
  mul x20, x5, x21
  fsub.2d v18, v10, v16
  umulh x5, x5, x21
  fmla.2d v18, v3, v5
  adds x4, x20, x4
  cinc x5, x5, hs
  add.2d v1, v1, v16
  add.2d v0, v0, v18
  adds x0, x4, x0
  cinc x4, x5, hs
  mov.16b v5, v9
  mul x5, x6, x21
  fmla.2d v5, v3, v6
  umulh x6, x6, x21
  fsub.2d v16, v10, v5
  fmla.2d v16, v3, v6
  adds x4, x5, x4
  cinc x5, x6, hs
  add.2d v2, v2, v5
  adds x1, x4, x1
  cinc x4, x5, hs
  add.2d v1, v1, v16
  mul x5, x7, x21
  mov.16b v5, v9
  fmla.2d v5, v3, v12
  umulh x6, x7, x21
  fsub.2d v6, v10, v5
  adds x4, x5, x4
  cinc x5, x6, hs
  fmla.2d v6, v3, v12
  adds x2, x4, x2
  cinc x4, x5, hs
  add.2d v5, v11, v5
  add.2d v2, v2, v6
  add x3, x3, x4
  mov.16b v6, v9
  mov x4, #65535
  fmla.2d v6, v3, v7
  movk x4, #61439, lsl 16
  fsub.2d v11, v10, v6
  fmla.2d v11, v3, v7
  movk x4, #62867, lsl 32
  add.2d v3, v14, v6
  movk x4, #49889, lsl 48
  add.2d v5, v5, v11
  mul x4, x4, x17
  usra.2d v15, v13, #52
  usra.2d v17, v15, #52
  mov x5, #1
  usra.2d v19, v17, #52
  movk x5, #61440, lsl 16
  usra.2d v4, v19, #52
  and.16b v6, v13, v8
  movk x5, #62867, lsl 32
  and.16b v7, v15, v8
  movk x5, #17377, lsl 48
  and.16b v11, v17, v8
  mov x6, #28817
  and.16b v8, v19, v8
  ucvtf.2d v6, v6
  movk x6, #31161, lsl 16
  mov x7, #37864
  movk x6, #59464, lsl 32
  movk x7, #1815, lsl 16
  movk x6, #10291, lsl 48
  movk x7, #28960, lsl 32
  movk x7, #17153, lsl 48
  mov x20, #22621
  dup.2d v12, x7
  movk x20, #33153, lsl 16
  mov.16b v13, v9
  movk x20, #17846, lsl 32
  fmla.2d v13, v6, v12
  fsub.2d v14, v10, v13
  movk x20, #47184, lsl 48
  fmla.2d v14, v6, v12
  mov x7, #41001
  add.2d v0, v0, v13
  movk x7, #57649, lsl 16
  add.2d v4, v4, v14
  mov x21, #46128
  movk x7, #20082, lsl 32
  movk x21, #29964, lsl 16
  movk x7, #12388, lsl 48
  movk x21, #7587, lsl 32
  mul x22, x5, x4
  movk x21, #17161, lsl 48
  dup.2d v12, x21
  umulh x5, x5, x4
  mov.16b v13, v9
  cmn x22, x17
  cinc x5, x5, hs
  fmla.2d v13, v6, v12
  mul x17, x6, x4
  fsub.2d v14, v10, v13
  fmla.2d v14, v6, v12
  umulh x6, x6, x4
  add.2d v1, v1, v13
  adds x5, x17, x5
  cinc x6, x6, hs
  add.2d v0, v0, v14
  mov x17, #52826
  adds x0, x5, x0
  cinc x5, x6, hs
  movk x17, #57790, lsl 16
  mul x6, x20, x4
  movk x17, #55431, lsl 32
  umulh x20, x20, x4
  movk x17, #17196, lsl 48
  dup.2d v12, x17
  adds x5, x6, x5
  cinc x6, x20, hs
  mov.16b v13, v9
  adds x1, x5, x1
  cinc x5, x6, hs
  fmla.2d v13, v6, v12
  mul x6, x7, x4
  fsub.2d v14, v10, v13
  fmla.2d v14, v6, v12
  umulh x4, x7, x4
  add.2d v2, v2, v13
  adds x5, x6, x5
  cinc x4, x4, hs
  add.2d v1, v1, v14
  adds x2, x5, x2
  cinc x4, x4, hs
  mov x5, #31276
  movk x5, #21262, lsl 16
  add x3, x3, x4
  movk x5, #2304, lsl 32
  mov x4, #2
  movk x5, #17182, lsl 48
  movk x4, #57344, lsl 16
  dup.2d v12, x5
  mov.16b v13, v9
  movk x4, #60199, lsl 32
  fmla.2d v13, v6, v12
  movk x4, #34755, lsl 48
  fsub.2d v14, v10, v13
  mov x5, #57634
  fmla.2d v14, v6, v12
  add.2d v5, v5, v13
  movk x5, #62322, lsl 16
  add.2d v2, v2, v14
  movk x5, #53392, lsl 32
  mov x6, #28672
  movk x5, #20583, lsl 48
  movk x6, #24515, lsl 16
  movk x6, #54929, lsl 32
  mov x7, #45242
  movk x6, #17064, lsl 48
  movk x7, #770, lsl 16
  dup.2d v12, x6
  mov.16b v13, v9
  movk x7, #35693, lsl 32
  fmla.2d v13, v6, v12
  movk x7, #28832, lsl 48
  fsub.2d v14, v10, v13
  mov x6, #16467
  fmla.2d v14, v6, v12
  add.2d v3, v3, v13
  movk x6, #49763, lsl 16
  add.2d v5, v5, v14
  movk x6, #40165, lsl 32
  ucvtf.2d v6, v7
  movk x6, #24776, lsl 48
  mov x17, #44768
  movk x17, #51919, lsl 16
  subs x4, x0, x4
  sbcs x5, x1, x5
  sbcs x7, x2, x7
  sbcs x6, x3, x6
  movk x17, #6346, lsl 32
  tst x3, #9223372036854775808
  csel x0, x4, x0, mi
  csel x1, x5, x1, mi
  csel x2, x7, x2, mi
  csel x3, x6, x3, mi
  movk x17, #17133, lsl 48
  mul x4, x8, x12
  dup.2d v7, x17
  mov.16b v12, v9
  umulh x5, x8, x12
  fmla.2d v12, v6, v7
  mul x6, x9, x12
  fsub.2d v13, v10, v12
  umulh x7, x9, x12
  fmla.2d v13, v6, v7
  add.2d v0, v0, v12
  adds x5, x6, x5
  cinc x6, x7, hs
  add.2d v4, v4, v13
  mul x7, x10, x12
  mov x17, #47492
  umulh x20, x10, x12
  movk x17, #23630, lsl 16
  movk x17, #49985, lsl 32
  adds x6, x7, x6
  cinc x7, x20, hs
  movk x17, #17168, lsl 48
  mul x20, x11, x12
  dup.2d v7, x17
  mov.16b v12, v9
  umulh x12, x11, x12
  fmla.2d v12, v6, v7
  adds x7, x20, x7
  cinc x12, x12, hs
  fsub.2d v13, v10, v12
  mul x17, x8, x13
  fmla.2d v13, v6, v7
  add.2d v1, v1, v12
  umulh x20, x8, x13
  add.2d v0, v0, v13
  adds x5, x17, x5
  cinc x17, x20, hs
  mov x20, #57936
  mul x21, x9, x13
  movk x20, #54828, lsl 16
  movk x20, #18292, lsl 32
  umulh x22, x9, x13
  movk x20, #17197, lsl 48
  adds x17, x21, x17
  cinc x21, x22, hs
  dup.2d v7, x20
  adds x6, x17, x6
  cinc x17, x21, hs
  mov.16b v12, v9
  fmla.2d v12, v6, v7
  mul x20, x10, x13
  fsub.2d v13, v10, v12
  umulh x21, x10, x13
  fmla.2d v13, v6, v7
  adds x17, x20, x17
  cinc x20, x21, hs
  add.2d v2, v2, v12
  add.2d v1, v1, v13
  adds x7, x17, x7
  cinc x17, x20, hs
  mov x20, #17708
  mul x21, x11, x13
  movk x20, #43915, lsl 16
  umulh x13, x11, x13
  movk x20, #64348, lsl 32
  movk x20, #17188, lsl 48
  adds x17, x21, x17
  cinc x13, x13, hs
  dup.2d v7, x20
  adds x12, x17, x12
  cinc x13, x13, hs
  mov.16b v12, v9
  mul x17, x8, x14
  fmla.2d v12, v6, v7
  fsub.2d v13, v10, v12
  umulh x20, x8, x14
  fmla.2d v13, v6, v7
  adds x6, x17, x6
  cinc x17, x20, hs
  add.2d v5, v5, v12
  add.2d v2, v2, v13
  mul x20, x9, x14
  mov x21, #29184
  umulh x22, x9, x14
  movk x21, #20789, lsl 16
  adds x17, x20, x17
  cinc x20, x22, hs
  movk x21, #19197, lsl 32
  movk x21, #17083, lsl 48
  adds x7, x17, x7
  cinc x17, x20, hs
  dup.2d v7, x21
  mul x20, x10, x14
  mov.16b v12, v9
  umulh x21, x10, x14
  fmla.2d v12, v6, v7
  fsub.2d v13, v10, v12
  adds x17, x20, x17
  cinc x20, x21, hs
  fmla.2d v13, v6, v7
  adds x12, x17, x12
  cinc x17, x20, hs
  add.2d v3, v3, v12
  mul x20, x11, x14
  add.2d v5, v5, v13
  ucvtf.2d v6, v11
  umulh x14, x11, x14
  mov x21, #58856
  adds x17, x20, x17
  cinc x14, x14, hs
  movk x21, #14953, lsl 16
  adds x13, x17, x13
  cinc x14, x14, hs
  movk x21, #15155, lsl 32
  movk x21, #17181, lsl 48
  mul x17, x8, x15
  dup.2d v7, x21
  umulh x8, x8, x15
  mov.16b v11, v9
  adds x7, x17, x7
  cinc x8, x8, hs
  fmla.2d v11, v6, v7
  fsub.2d v12, v10, v11
  mul x17, x9, x15
  fmla.2d v12, v6, v7
  umulh x9, x9, x15
  add.2d v0, v0, v11
  adds x8, x17, x8
  cinc x9, x9, hs
  add.2d v4, v4, v12
  mov x17, #35392
  adds x8, x8, x12
  cinc x9, x9, hs
  movk x17, #12477, lsl 16
  mul x12, x10, x15
  movk x17, #56780, lsl 32
  movk x17, #17142, lsl 48
  umulh x10, x10, x15
  dup.2d v7, x17
  adds x9, x12, x9
  cinc x10, x10, hs
  mov.16b v11, v9
  adds x9, x9, x13
  cinc x10, x10, hs
  fmla.2d v11, v6, v7
  fsub.2d v12, v10, v11
  mul x12, x11, x15
  fmla.2d v12, v6, v7
  umulh x11, x11, x15
  add.2d v1, v1, v11
  adds x10, x12, x10
  cinc x11, x11, hs
  add.2d v0, v0, v12
  mov x12, #9848
  adds x10, x10, x14
  cinc x11, x11, hs
  movk x12, #54501, lsl 16
  mov x13, #48718
  movk x12, #31540, lsl 32
  movk x13, #4732, lsl 16
  movk x12, #17170, lsl 48
  dup.2d v7, x12
  movk x13, #45078, lsl 32
  mov.16b v11, v9
  movk x13, #39852, lsl 48
  fmla.2d v11, v6, v7
  mov x12, #16676
  fsub.2d v12, v10, v11
  fmla.2d v12, v6, v7
  movk x12, #12692, lsl 16
  add.2d v2, v2, v11
  movk x12, #20986, lsl 32
  add.2d v1, v1, v12
  movk x12, #2848, lsl 48
  mov x14, #9584
  movk x14, #63883, lsl 16
  mov x15, #51052
  movk x14, #18253, lsl 32
  movk x15, #24721, lsl 16
  movk x14, #17190, lsl 48
  movk x15, #61092, lsl 32
  dup.2d v7, x14
  mov.16b v11, v9
  movk x15, #45156, lsl 48
  fmla.2d v11, v6, v7
  mov x14, #3197
  fsub.2d v12, v10, v11
  fmla.2d v12, v6, v7
  movk x14, #18936, lsl 16
  add.2d v5, v5, v11
  movk x14, #10922, lsl 32
  add.2d v2, v2, v12
  movk x14, #11014, lsl 48
  mov x17, #51712
  movk x17, #16093, lsl 16
  mul x20, x13, x4
  movk x17, #30633, lsl 32
  umulh x13, x13, x4
  movk x17, #17068, lsl 48
  adds x7, x20, x7
  cinc x13, x13, hs
  dup.2d v7, x17
  mov.16b v11, v9
  mul x17, x12, x4
  fmla.2d v11, v6, v7
  umulh x12, x12, x4
  fsub.2d v12, v10, v11
  adds x13, x17, x13
  cinc x12, x12, hs
  fmla.2d v12, v6, v7
  add.2d v3, v3, v11
  adds x8, x13, x8
  cinc x12, x12, hs
  add.2d v5, v5, v12
  mul x13, x15, x4
  ucvtf.2d v6, v8
  umulh x15, x15, x4
  mov x17, #34724
  movk x17, #40393, lsl 16
  adds x12, x13, x12
  cinc x13, x15, hs
  movk x17, #23752, lsl 32
  adds x9, x12, x9
  cinc x12, x13, hs
  movk x17, #17184, lsl 48
  mul x13, x14, x4
  dup.2d v7, x17
  mov.16b v8, v9
  umulh x4, x14, x4
  fmla.2d v8, v6, v7
  adds x12, x13, x12
  cinc x4, x4, hs
  fsub.2d v11, v10, v8
  adds x10, x12, x10
  cinc x4, x4, hs
  fmla.2d v11, v6, v7
  add.2d v0, v0, v8
  add x4, x11, x4
  add.2d v4, v4, v11
  mov x11, #56431
  mov x12, #25532
  movk x12, #31025, lsl 16
  movk x11, #30457, lsl 16
  movk x12, #10002, lsl 32
  movk x11, #30012, lsl 32
  movk x12, #17199, lsl 48
  movk x11, #6382, lsl 48
  dup.2d v7, x12
  mov.16b v8, v9
  mov x12, #59151
  fmla.2d v8, v6, v7
  movk x12, #41769, lsl 16
  fsub.2d v11, v10, v8
  movk x12, #32276, lsl 32
  fmla.2d v11, v6, v7
  add.2d v1, v1, v8
  movk x12, #21677, lsl 48
  add.2d v0, v0, v11
  mov x13, #34015
  mov x14, #18830
  movk x13, #20342, lsl 16
  movk x14, #2465, lsl 16
  movk x14, #36348, lsl 32
  movk x13, #13935, lsl 32
  movk x14, #17194, lsl 48
  movk x13, #11030, lsl 48
  dup.2d v7, x14
  mov x14, #13689
  mov.16b v8, v9
  fmla.2d v8, v6, v7
  movk x14, #8159, lsl 16
  fsub.2d v11, v10, v8
  movk x14, #215, lsl 32
  fmla.2d v11, v6, v7
  movk x14, #4913, lsl 48
  add.2d v2, v2, v8
  add.2d v1, v1, v11
  mul x15, x11, x5
  mov x17, #21566
  umulh x11, x11, x5
  movk x17, #43708, lsl 16
  adds x7, x15, x7
  cinc x11, x11, hs
  movk x17, #57685, lsl 32
  movk x17, #17185, lsl 48
  mul x15, x12, x5
  dup.2d v7, x17
  umulh x12, x12, x5
  mov.16b v8, v9
  fmla.2d v8, v6, v7
  adds x11, x15, x11
  cinc x12, x12, hs
  fsub.2d v11, v10, v8
  adds x8, x11, x8
  cinc x11, x12, hs
  fmla.2d v11, v6, v7
  mul x12, x13, x5
  add.2d v5, v5, v8
  add.2d v2, v2, v11
  umulh x13, x13, x5
  mov x15, #3072
  adds x11, x12, x11
  cinc x12, x13, hs
  movk x15, #8058, lsl 16
  adds x9, x11, x9
  cinc x11, x12, hs
  movk x15, #46097, lsl 32
  movk x15, #17047, lsl 48
  mul x12, x14, x5
  dup.2d v7, x15
  umulh x5, x14, x5
  mov.16b v8, v9
  adds x11, x12, x11
  cinc x5, x5, hs
  fmla.2d v8, v6, v7
  fsub.2d v11, v10, v8
  adds x10, x11, x10
  cinc x5, x5, hs
  fmla.2d v11, v6, v7
  add x4, x4, x5
  add.2d v3, v3, v8
  mov x5, #61005
  add.2d v5, v5, v11
  mov x11, #65535
  movk x5, #58262, lsl 16
  movk x11, #61439, lsl 16
  movk x5, #32851, lsl 32
  movk x11, #62867, lsl 32
  movk x5, #11582, lsl 48
  movk x11, #1, lsl 48
  umov x12, v4.d[0]
  mov x13, #37581
  umov x14, v4.d[1]
  movk x13, #43836, lsl 16
  mul x12, x12, x11
  movk x13, #36286, lsl 32
  mul x11, x14, x11
  and x12, x12, x16
  movk x13, #51783, lsl 48
  and x11, x11, x16
  mov x14, #10899
  ins v6.d[0], x12
  ins v6.d[1], x11
  ucvtf.2d v6, v6
  movk x14, #30709, lsl 16
  mov x11, #16
  movk x14, #61551, lsl 32
  movk x11, #22847, lsl 32
  movk x14, #45784, lsl 48
  movk x11, #17151, lsl 48
  dup.2d v7, x11
  mov x11, #36612
  mov.16b v8, v9
  movk x11, #63402, lsl 16
  fmla.2d v8, v6, v7
  movk x11, #47623, lsl 32
  fsub.2d v11, v10, v8
  fmla.2d v11, v6, v7
  movk x11, #9430, lsl 48
  add.2d v0, v0, v8
  mul x12, x5, x6
  add.2d v4, v4, v11
  umulh x5, x5, x6
  mov x15, #20728
  movk x15, #23588, lsl 16
  adds x7, x12, x7
  cinc x5, x5, hs
  movk x15, #7790, lsl 32
  mul x12, x13, x6
  movk x15, #17170, lsl 48
  umulh x13, x13, x6
  dup.2d v7, x15
  mov.16b v8, v9
  adds x5, x12, x5
  cinc x12, x13, hs
  fmla.2d v8, v6, v7
  adds x5, x5, x8
  cinc x8, x12, hs
  fsub.2d v11, v10, v8
  mul x12, x14, x6
  fmla.2d v11, v6, v7
  add.2d v1, v1, v8
  umulh x13, x14, x6
  add.2d v0, v0, v11
  adds x8, x12, x8
  cinc x12, x13, hs
  mov x13, #16000
  adds x8, x8, x9
  cinc x9, x12, hs
  movk x13, #53891, lsl 16
  movk x13, #5509, lsl 32
  mul x12, x11, x6
  movk x13, #17144, lsl 48
  umulh x6, x11, x6
  dup.2d v7, x13
  mov.16b v8, v9
  adds x9, x12, x9
  cinc x6, x6, hs
  fmla.2d v8, v6, v7
  adds x9, x9, x10
  cinc x6, x6, hs
  fsub.2d v11, v10, v8
  add x4, x4, x6
  fmla.2d v11, v6, v7
  add.2d v2, v2, v8
  mov x6, #65535
  add.2d v1, v1, v11
  movk x6, #61439, lsl 16
  mov x10, #46800
  movk x6, #62867, lsl 32
  movk x10, #2568, lsl 16
  movk x10, #1335, lsl 32
  movk x6, #49889, lsl 48
  movk x10, #17188, lsl 48
  mul x6, x6, x7
  dup.2d v7, x10
  mov x10, #1
  mov.16b v8, v9
  fmla.2d v8, v6, v7
  movk x10, #61440, lsl 16
  fsub.2d v11, v10, v8
  movk x10, #62867, lsl 32
  fmla.2d v11, v6, v7
  movk x10, #17377, lsl 48
  add.2d v5, v5, v8
  add.2d v2, v2, v11
  mov x11, #28817
  mov x12, #39040
  movk x11, #31161, lsl 16
  movk x12, #14704, lsl 16
  movk x11, #59464, lsl 32
  movk x12, #12839, lsl 32
  movk x12, #17096, lsl 48
  movk x11, #10291, lsl 48
  dup.2d v7, x12
  mov x12, #22621
  mov.16b v8, v9
  movk x12, #33153, lsl 16
  fmla.2d v8, v6, v7
  fsub.2d v9, v10, v8
  movk x12, #17846, lsl 32
  fmla.2d v9, v6, v7
  movk x12, #47184, lsl 48
  add.2d v3, v3, v8
  add.2d v5, v5, v9
  mov x13, #41001
  mov x14, #140737488355328
  movk x13, #57649, lsl 16
  dup.2d v6, x14
  movk x13, #20082, lsl 32
  and.16b v6, v3, v6
  cmeq.2d v6, v6, #0
  movk x13, #12388, lsl 48
  mov x14, #2
  mul x15, x10, x6
  movk x14, #57344, lsl 16
  umulh x10, x10, x6
  movk x14, #60199, lsl 32
  movk x14, #3, lsl 48
  cmn x15, x7
  cinc x10, x10, hs
  dup.2d v7, x14
  mul x7, x11, x6
  bic.16b v7, v7, v6
  umulh x11, x11, x6
  mov x14, #10364
  movk x14, #11794, lsl 16
  adds x7, x7, x10
  cinc x10, x11, hs
  movk x14, #3895, lsl 32
  adds x5, x7, x5
  cinc x7, x10, hs
  movk x14, #9, lsl 48
  mul x10, x12, x6
  dup.2d v8, x14
  bic.16b v8, v8, v6
  umulh x11, x12, x6
  mov x12, #26576
  adds x7, x10, x7
  cinc x10, x11, hs
  movk x12, #47696, lsl 16
  adds x7, x7, x8
  cinc x8, x10, hs
  movk x12, #688, lsl 32
  movk x12, #3, lsl 48
  mul x10, x13, x6
  dup.2d v9, x12
  umulh x6, x13, x6
  bic.16b v9, v9, v6
  adds x8, x10, x8
  cinc x6, x6, hs
  mov x10, #46800
  movk x10, #2568, lsl 16
  adds x8, x8, x9
  cinc x6, x6, hs
  movk x10, #1335, lsl 32
  add x9, x4, x6
  movk x10, #4, lsl 48
  dup.2d v10, x10
  mov x4, #2
  bic.16b v10, v10, v6
  movk x4, #57344, lsl 16
  mov x6, #49763
  movk x4, #60199, lsl 32
  movk x6, #40165, lsl 16
  movk x6, #24776, lsl 32
  movk x4, #34755, lsl 48
  dup.2d v11, x6
  mov x6, #57634
  bic.16b v6, v11, v6
  movk x6, #62322, lsl 16
  sub.2d v0, v0, v7
  ssra.2d v0, v4, #52
  movk x6, #53392, lsl 32
  sub.2d v4, v1, v8
  movk x6, #20583, lsl 48
  ssra.2d v4, v0, #52
  mov x10, #45242
  sub.2d v7, v2, v9
  ssra.2d v7, v4, #52
  movk x10, #770, lsl 16
  sub.2d v5, v5, v10
  movk x10, #35693, lsl 32
  ssra.2d v5, v7, #52
  movk x10, #28832, lsl 48
  sub.2d v6, v3, v6
  ssra.2d v6, v5, #52
  mov x11, #16467
  ushr.2d v1, v4, #12
  movk x11, #49763, lsl 16
  ushr.2d v2, v7, #24
  movk x11, #40165, lsl 32
  ushr.2d v3, v5, #36
  sli.2d v0, v4, #52
  movk x11, #24776, lsl 48
  sli.2d v1, v7, #40
  subs x4, x5, x4
  sbcs x6, x7, x6
  sbcs x10, x8, x10
  sbcs x11, x9, x11
  sli.2d v2, v5, #28
  sli.2d v3, v6, #16
  tst x9, #9223372036854775808
  csel x4, x4, x5, mi
  csel x5, x6, x7, mi
  csel x6, x10, x8, mi
  csel x7, x11, x9, mi
