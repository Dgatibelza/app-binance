/*******************************************************************************
*   (c) 2016 Ledger
*   (c) 2018 ZondaX GmbH
*   (c) 2019 Binance
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
#ifdef HAVE_NBGL
#include <stdbool.h>

#include "view.h"
#include "view_old.h"
#include "common.h"


#include "os.h"
#include "cx.h"


#include "glyphs.h"

#include <string.h>
#include <stdio.h>

#define TRUE  1
#define FALSE 0

enum UI_STATE view_uiState;

void reject(unsigned int unused);



//------ Event handlers
/// view_set_handlers
void view_set_handlers(viewctl_delegate_getData func_getData,
                       viewctl_delegate_accept func_accept,
                       viewctl_delegate_reject func_reject){};

//------ Common functions

/// view_display_tx_menu
void view_display_tx_menu(unsigned int ignored){};

/// view_address_show_main_net
void view_address_show_main_net(unsigned int unused){};

/// view_address_show_test_net
void view_address_show_test_net(unsigned int unused){};

/// view_tx_show
void view_tx_show(unsigned int start_page){};

/// view_sign_transaction
void view_sign_transaction(unsigned int start_page){};

/// view_addr_show
void view_addr_show(unsigned int start_page){};

/// view_addr_confirm
void view_addr_confirm(unsigned int start_page){};

/// view_display_signing_success
void view_display_signing_success(){};

/// view_display_signing_error
void view_display_signing_error(){};

#endif // HAVE_NBGL