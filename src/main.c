/*******************************************************************************
*   (c) 2016 Ledger
*   (c) 2018 ZondaX GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
#include "app_main.h"

#include "crypto.h"
#include "view.h"

#include <os_io_seproxyhal.h>

__attribute__((section(".boot"))) int
main(void) {
    // exit critical section
    __asm volatile("cpsie i");

    view_init();
    os_boot();

    BEGIN_TRY
    {
        TRY
        {
            app_init();
            // set the default bip32 path
            uint32_t new_bip32_path[] = {
                44 | 0x80000000,  // purpose
                714 | 0x80000000,  // coin type (chain ID)
                0 | 0x80000000,  // account
                0,               // change (no change addresses for now)
                0,               // address index
            };
            memcpy(hdPath, new_bip32_path, sizeof(new_bip32_path));
            app_main();
        }
        CATCH_OTHER(e)
        {}
        FINALLY
        {}
    }
    END_TRY;
}
