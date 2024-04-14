#include "../config.h"
#include "../parser/sdp/sdp.h"
#include "../parser/parse_uri.c"
#include "../parser/parse_hname2.h"
#include "../parser/contact/parse_contact.h"
#include "../parser/parse_from.h"
#include "../parser/parse_to.h"
#include "../parser/parse_rr.h"
#include "../parser/parse_refer_to.h"
#include "../parser/parse_ppi_pai.h"
#include "../parser/parse_privacy.h"
#include "../parser/parse_diversion.h"
#include "../parser/parse_identityinfo.h"
#include "../parser/parse_disposition.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	if(Size == 0)
		return 0;

	// Ensure that the input data is a null-terminated string
	uint8_t *null_terminated_data = (uint8_t *)malloc(Size + 1);
	if(!null_terminated_data)
		return 0;
	memcpy(null_terminated_data, Data, Size);
	null_terminated_data[Size] = '\0';

	// Create a sip_msg struct and set its buf and len fields
	struct sip_msg msg;
	msg.buf = (char *)null_terminated_data;
	msg.len = Size;

	// Call the target function to be fuzzed
	parse_refer_to_header(&msg);

	// Clean up memory
	free(null_terminated_data);

	return 0;
}