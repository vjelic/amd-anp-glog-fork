
//
// Copyright(C) Advanced Micro Devices, Inc. All rights reserved.
//
// You may not use this software and documentation (if any) (collectively,
// the "Materials") except in compliance with the terms and conditions of
// the Software License Agreement included with the Materials or otherwise as
// set forth in writing and signed by you and an authorized signatory of AMD.
// If you do not have a copy of the Software License Agreement, contact your
// AMD representative for a copy.
//
// You agree that you will not reverse engineer or decompile the Materials,
// in whole or in part, except as allowed by applicable law.
//
// THE MATERIALS ARE DISTRIBUTED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OR
// REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
//

#include <sys/types.h>
#include <unistd.h>

extern "C" {
#include "infiniband/ionic_dv.h"
}

int wrap_ionic_dv_qp_set_gda(struct ibv_qp *ibqp, bool enable_send, bool enable_recv) {
  return ionic_dv_qp_set_gda(ibqp, enable_send, enable_recv);
}

int wrap_ibv_pd_set_udma_mask(struct ibv_pd *ibpd, uint8_t udma_mask) {
  return ionic_dv_pd_set_udma_mask(ibpd, udma_mask);
}
