#include <stddef.h>
#include <stdlib.h>
#include <rpm/rpmio.h>
#if defined __has_include
# if __has_include(<rpm/rpmcrypto.h>)
#  include <rpm/rpmcrypto.h>
# endif
#endif
#include <rpm/rpmkeyring.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmpgp.h>
#include <rpm/rpmts.h>
typedef struct DIGEST_CTX_s * DIGEST_CTX;

__attribute__((unused)) static void bogus(void) {
    (void)rpmDigestDup;
    (void)rpmDigestLength;
    (void)rpmDigestInit;
    (void)rpmDigestUpdate;
    (void)rpmDigestFinal;
    (void)rpmReadConfigFiles;
    (void)rpmPushMacro;
    (void)pgpPrtParams;
    (void)pgpDigParamsFree;
    (void)pgpDigParamsAlgo;
    (void)rpmtsCreate;
    (void)rpmtsLink;
    (void)rpmtsFree;
    (void)rpmKeyringLink;
    (void)rpmKeyringFree;
    (void)rpmtsGetKeyring;
}

struct DIGEST_CTX_s *qubes_rpm_rpmDigestDup(DIGEST_CTX octx) {
    return rpmDigestDup(octx);
}
size_t qubes_rpm_rpmDigestLength(int hashalgo) {
    return rpmDigestLength(hashalgo);
}
DIGEST_CTX qubes_rpm_rpmDigestInit(int hashalgo, uint32_t flags) {
    return rpmDigestInit(hashalgo, flags);
}
int qubes_rpm_rpmDigestUpdate(DIGEST_CTX ctx, const void *data, size_t len) {
    return rpmDigestUpdate(ctx, data, len);
}
int qubes_rpm_rpmDigestFinal(DIGEST_CTX ctx, void ** datap, size_t * lenp, int asAscii) {
    return rpmDigestFinal(ctx, datap, lenp, asAscii);
}
int qubes_rpm_rpmReadConfigFiles(const char *file, const char *target) {
    return rpmReadConfigFiles(file, target);
}
int qubes_rpm_rpmPushMacro(struct rpmMacroContext_s *mc, const char *n, const char *o, const char *b, int level) {
    return rpmPushMacro(mc, n, o, b, level);
}
int qubes_rpm_pgpPrtParams(const uint8_t *pkts, size_t pktlen, unsigned int pkttype, pgpDigParams *ret) {
    return pgpPrtParams(pkts, pktlen, pkttype, ret);
}
struct pgpDigParams_s *qubes_rpm_pgpDigParamsFree(struct pgpDigParams_s *params) {
    return pgpDigParamsFree(params);
}
unsigned int qubes_rpm_pgpDigParamsAlgo(struct pgpDigParams_s *digp, unsigned int algotype) {
    return pgpDigParamsAlgo(digp, algotype);
}
struct rpmts_s *qubes_rpm_rpmtsCreate(void) {
    return rpmtsCreate();
}
struct rpmts_s *qubes_rpm_rpmtsLink(struct rpmts_s *ts) {
    return rpmtsLink(ts);
}
struct rpmts_s *qubes_rpm_rpmtsFree(struct rpmts_s *ts) {
    return rpmtsFree(ts);
}
struct rpmKeyring_s *qubes_rpm_rpmKeyringLink(struct rpmKeyring_s *keyring) {
    return rpmKeyringLink(keyring);
}
struct rpmKeyring_s *qubes_rpm_rpmKeyringFree(struct rpmKeyring_s *keyring) {
    return rpmKeyringFree(keyring);
}
struct rpmKeyring_s *qubes_rpm_rpmtsGetKeyring(struct rpmts_s *ts, int autoload) {
    return rpmtsGetKeyring(ts, autoload);
}
unsigned int qubes_rpm_rpmTagGetType(unsigned int a) {
    return rpmTagGetType(a);
}
unsigned int qubes_rpm_rpmTagTypeGetClass(unsigned int a) {
    return rpmTagTypeGetClass(a);
}
unsigned int qubes_rpm_rpmKeyringVerifySig(rpmKeyring keyring, pgpDigParams sig, DIGEST_CTX ctx) {
    return rpmKeyringVerifySig(keyring, sig, ctx);
}

/* This comes *after* the above definitions, to ensure a compile error if the proper declarations are not visible
 * in the included headers.  Otherwise the compiler would silently do the wrong thing! */
rpmRC rpmKeyringVerifySig(struct rpmKeyring_s *keyring, struct pgpDigParams_s *sig, DIGEST_CTX ctx);
struct DIGEST_CTX_s *rpmDigestDup(DIGEST_CTX octx);
size_t rpmDigestLength(int hashalgo);
DIGEST_CTX rpmDigestInit(int hashalgo, uint32_t flags);
int rpmDigestUpdate(DIGEST_CTX ctx, const void *data, size_t len);
int rpmDigestFinal(DIGEST_CTX ctx, void ** datap, size_t * lenp, int asAscii);
int rpmReadConfigFiles(const char *file, const char *target);
int rpmPushMacro(struct rpmMacroContext_s *mc, const char *n, const char *o, const char *b, int level);
int pgpPrtParams(const uint8_t *pkts, size_t pktlen, unsigned int pkttype, pgpDigParams *ret);
struct pgpDigParams_s *pgpDigParamsFree(struct pgpDigParams_s *);
unsigned int pgpDigParamsAlgo(struct pgpDigParams_s *digp, unsigned int algotype);
struct rpmts_s *rpmtsCreate(void);
struct rpmts_s *rpmtsLink(struct rpmts_s *);
struct rpmts_s *rpmtsFree(struct rpmts_s *);
struct rpmKeyring_s *rpmKeyringLink(struct rpmKeyring_s *keyring);
struct rpmKeyring_s *rpmKeyringFree(struct rpmKeyring_s *keyring);
struct rpmKeyring_s *rpmtsGetKeyring(struct rpmts_s *ts, int autoload);
#if 0 // the API changed in RPM 4.19 but implicit conversions
      // allow for compatibility
enum rpmTagType_e rpmTagGetType(int);
#endif
enum rpmTagClass_e rpmTagTypeGetClass(enum rpmTagType_e);
