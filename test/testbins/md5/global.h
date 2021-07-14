/* GLOBAL.H - RSAREF types and constants
 */

#ifndef PROTOTYPES
#define PROTOTYPES 0
#endif

#include <stdint.h>

/* POINTER defines a generic pointer type */
typedef uint8_t *POINTER;

/* UINT2 defines a two byte word */
typedef uint16_t UINT2;

/* UINT4 defines a four byte word */
typedef uint32_t UINT4;

/* PROTO_LIST is defined depending on how PROTOTYPES is defined above.
If using PROTOTYPES, then PROTO_LIST returns the list, otherwise it
  returns an empty list.
 */
#if PROTOTYPES
#define PROTO_LIST(list) list
#else
#define PROTO_LIST(list) ()
#endif

