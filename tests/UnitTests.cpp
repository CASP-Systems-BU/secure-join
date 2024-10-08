#include "UnitTests.h"

#include "LowMCPerm_Test.h"
#include "PaillierPerm_Test.h"
#include "ComposedPerm_Test.h"
#include "AltModWPrf_Test.h"
#include "GMW_Test.h"
#include "RadixSort_Test.h"

#include <functional>

#include "PermCor_Test.h"
#include "AltModPerm_Test.h"
#include "PaillierPerm_Test.h"
#include "ComposedPerm_Test.h"
#include "AdditivePerm_Test.h"
#include "CSVParser_Test.h"

#include "AggTree_Tests.h"
#include "OmJoin_Test.h"
#include "CWrapper_Test.h"
#include "CorGenerator_Test.h"
#include "Average_Test.h"
#include "Where_Test.h"
#include "F4Vole_Test.h"

namespace secJoin_Tests
{
    oc::TestCollection Tests(
        [](oc::TestCollection& t)
        {


            t.add("F4Vole_Silent_paramSweep_test                 ", F4Vole_Silent_paramSweep_test);
            t.add("CorGenerator_Ot_Test                          ", CorGenerator_Ot_Test);
            t.add("CorGenerator_BinOle_Test                      ", CorGenerator_BinOle_Test);
            t.add("CorGenerator_F4BitOt_Test                     ", CorGenerator_F4BitOt_Test);
            t.add("CorGenerator_TritOt_Test                      ", CorGenerator_TritOt_Test);
            t.add("CorGenerator_mixed_Test                       ", CorGenerator_mixed_Test);
            

            t.add("Gmw_half_test                                 ", Gmw_half_test);
            t.add("Gmw_basic_test                                ", Gmw_basic_test);
            t.add("Gmw_inOut_test                                ", Gmw_inOut_test);
            t.add("Gmw_gate_test                                 ", Gmw_gate_test);
            t.add("Gmw_xor_and_test                              ", Gmw_xor_and_test);
            t.add("Gmw_aa_na_and_test                            ", Gmw_aa_na_and_test);
            t.add("Gmw_add_test                                  ", Gmw_add_test);
            t.add("Gmw_noLevelize_test                           ", Gmw_noLevelize_test);


            t.add("F2LinearCode_test                              ", F2LinearCode_test);
            t.add("AltModWPrf_mod3BitDecompostion_test            ", AltModWPrf_mod3BitDecompostion_test);

            t.add("AltModWPrf_AMult_test                          ", AltModWPrf_AMult_test);
            t.add("AltModWPrf_BMult_test                          ", AltModWPrf_BMult_test);
            t.add("AltModWPrf_correction_test                     ", AltModWPrf_correction_test);

            t.add("AltModWPrf_sampleMod3_test                     ", AltModWPrf_sampleMod3_test);
            t.add("AltModWPrf_mod3_test                           ", AltModWPrf_mod3_test);
            t.add("AltModWPrf_mod2Ole_test                        ", AltModWPrf_mod2Ole_test);
            t.add("AltModWPrf_mod2OtF4_test                       ", AltModWPrf_mod2OtF4_test);
            
            t.add("AltModWPrf_plain_test                          ", AltModWPrf_plain_test);
            t.add("AltModWPrf_proto_test                          ", AltModWPrf_proto_test);
            t.add("AltModWPrf_sharedKey_test                      ", AltModWPrf_sharedKey_test);
            t.add("AltModWPrf_shared_test                         ", AltModWPrf_shared_test);
            
            t.add("plaintext_perm_test                           ", plaintext_perm_test);
            t.add("PermCor_apply_test                            ", PermCor_apply_test);
            t.add("PermCor_sharedApply_test                      ", PermCor_sharedApply_test);

            t.add("ComposedPerm_apply_test                       ", ComposedPerm_apply_test);
            t.add("ComposedPerm_compose_test                     ", ComposedPerm_compose_test);
            t.add("ComposedPerm_derandomize_test                 ", ComposedPerm_derandomize_test);

            t.add("AltModPerm_setup_test                         ", AltModPerm_setup_test);
            t.add("AltModComposedPerm_setup_test                 ", AltModComposedPerm_setup_test);

            t.add("LowMC_eval_test                               ", LowMC_eval_test);
            t.add("LowMCPerm_perm_test                           ", LowMCPerm_perm_test);
            t.add("LowMCPerm_secret_shared_input_perm_test       ", LowMCPerm_secret_shared_input_perm_test);

            t.add("RadixSort_aggregateSum_test                   ", RadixSort_aggregateSum_test);
            t.add("RadixSort_oneHot_test                         ", RadixSort_oneHot_test);
            t.add("RadixSort_bitInjection_test                   ", RadixSort_bitInjection_test);
            t.add("RadixSort_genValMasks2_test                   ", RadixSort_genValMasks2_test);
            t.add("RadixSort_hadamardSum_test                    ", RadixSort_hadamardSum_test);
            t.add("RadixSort_genBitPerm_test                     ", RadixSort_genBitPerm_test);
            t.add("RadixSort_genPerm_test                        ", RadixSort_genPerm_test);
            t.add("RadixSort_mock_test                           ", RadixSort_mock_test);


            t.add("secret_share_table_test                       ", secret_share_table_test);
            t.add("table_write_csv_test                          ", table_write_csv_test);
            t.add("table_write_bin_csv_test                      ", table_write_bin_csv_test);


            t.add("AggTree_plain_Test                            ", AggTree_plain_Test);
            t.add("AggTree_levelReveal_Test                      ", AggTree_levelReveal_Test);
            t.add("AggTree_dup_pre_levelReveal_Test              ", AggTree_dup_pre_levelReveal_Test);
            t.add("AggTree_dup_singleSetLeaves_Test              ", AggTree_dup_singleSetLeaves_Test);
            t.add("AggTree_dup_setLeaves_Test                    ", AggTree_dup_setLeaves_Test);
            t.add("AggTree_dup_upstream_cir_Test                 ", AggTree_dup_upstream_cir_Test);
            t.add("AggTree_xor_upstream_Test                     ", AggTree_xor_upstream_Test);
            t.add("AggTree_dup_pre_downstream_cir_Test           ", AggTree_dup_pre_downstream_cir_Test);
            t.add("AggTree_dup_downstream_Test                   ", AggTree_dup_downstream_Test);
            t.add("AggTree_xor_full_downstream_Test              ", AggTree_xor_full_downstream_Test);
            t.add("AggTree_xor_Partial_downstream_Test           ", AggTree_xor_Partial_downstream_Test);
            t.add("AggTree_dup_pre_full_Test                     ", AggTree_dup_pre_full_Test);
            t.add("AggTree_xor_pre_full_Test                     ", AggTree_xor_pre_full_Test);

            t.add("OmJoin_loadKeys_Test                          ", OmJoin_loadKeys_Test);
            t.add("OmJoin_getControlBits_Test                    ", OmJoin_getControlBits_Test);
            t.add("OmJoin_concatColumns_Test                     ", OmJoin_concatColumns_Test);
            t.add("OmJoin_getOutput_Test                         ", OmJoin_getOutput_Test);
            t.add("OmJoin_join_Test                              ", OmJoin_join_Test);
            t.add("OmJoin_join_BigKey_Test                       ", OmJoin_join_BigKey_Test);
            t.add("OmJoin_join_Reveal_Test                       ", OmJoin_join_Reveal_Test);
            t.add("OmJoin_join_round_Test                        ", OmJoin_join_round_Test);

            t.add("OmJoin_wrapper_join_test                      ", OmJoin_wrapper_join_test);
            t.add("OmJoin_wrapper_avg_test                       ", OmJoin_wrapper_avg_test);
            t.add("OmJoin_wrapper_where_test                     ", OmJoin_wrapper_where_test);


            t.add("Average_concatColumns_Test                    ", Average_concatColumns_Test);
            t.add("Average_getControlBits_Test                   ", Average_getControlBits_Test);
            t.add("Average_avg_Test                              ", Average_avg_Test);
            t.add("Average_avg_BigKey_Test                       ", Average_avg_BigKey_Test);

            t.add("Where_genWhBundle_Test                        ", Where_genWhBundle_Test);
            t.add("Where_ArrType_Equals_Test                     ", Where_ArrType_Equals_Test);
            t.add("Where_ArrType_Not_Equals_Test                 ", Where_ArrType_Not_Equals_Test);
            t.add("Where_ArrType_Less_Than_Test                  ", Where_ArrType_Less_Than_Test);
            t.add("Where_ArrType_Greater_Than_Equals_Test        ", Where_ArrType_Greater_Than_Equals_Test);
            t.add("Where_ArrType_Addition_Test                   ", Where_ArrType_Addition_Test);
            t.add("Where_ArrType_And_Or_Test                     ", Where_ArrType_And_Or_Test);
            t.add("Where_Cross_ArrType_Test                      ", Where_Cross_ArrType_Test);


        });
}
