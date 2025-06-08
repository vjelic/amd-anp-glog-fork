
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

#ifndef ANP_IBVWRAP_H_
#define ANP_IBVWRAP_H_

#include "ibvwrap.h"

int wrap_ibv_pd_set_udma_mask(struct ibv_pd *ibpd, uint8_t udma_mask);
int wrap_ionic_dv_qp_set_gda(struct ibv_qp *ibqp, bool enable_send, bool enable_recv);

#endif //End include guard
