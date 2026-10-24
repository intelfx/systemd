/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "ask-password-api.h"
#include "blockdev-util.h"
#include "cryptenroll-password.h"
#include "cryptsetup-util.h"
#include "device-util.h"
#include "env-util.h"
#include "errno-util.h"
#include "escape.h"
#include "fileio.h"
#include "iovec-util.h"
#include "log.h"
#include "password-quality-util.h"
#include "path-util.h"
#include "random-util.h"
#include "string-util.h"
#include "strv.h"

#define AUTO_KEYFILE_SIZE 64U

int load_volume_key_empty(
                const EnrollContext *c,
                struct crypt_device *cd,
                struct iovec *ret_vk) {

        int r;

        assert_se(c);
        assert_se(cd);
        assert_se(ret_vk);

        r = sym_crypt_volume_key_get(
                        cd,
                        CRYPT_ANY_SLOT,
                        ret_vk->iov_base,
                        &ret_vk->iov_len,
                        "",
                        0);
        if (r < 0)
                return log_error_errno(r, "Provided empty password did not work: %m");

        return r;
}

int load_volume_key_keyfile(
                const EnrollContext *c,
                struct crypt_device *cd,
                struct iovec *ret_vk) {

        _cleanup_(erase_and_freep) char *password = NULL;
        size_t password_len;
        int r;

        assert_se(c);
        assert_se(cd);
        assert_se(ret_vk);

        r = read_full_file_full(
                        AT_FDCWD,
                        c->unlock_keyfile,
                        UINT64_MAX,
                        4U * U64_MB, /* safety net */
                        READ_FULL_FILE_SECURE|READ_FULL_FILE_WARN_WORLD_READABLE|READ_FULL_FILE_CONNECT_SOCKET|READ_FULL_FILE_FAIL_WHEN_LARGER,
                        NULL,
                        &password,
                        &password_len);
        if (r < 0)
                return log_error_errno(r, "Reading keyfile %s failed: %m", c->unlock_keyfile);

        r = sym_crypt_volume_key_get(
                        cd,
                        CRYPT_ANY_SLOT,
                        ret_vk->iov_base,
                        &ret_vk->iov_len,
                        password,
                        password_len);
        if (r < 0)
                return log_error_errno(r, "Unlocking via keyfile failed: %m");

        return r;
}

int load_volume_key_password(
                const EnrollContext *c,
                struct crypt_device *cd,
                struct iovec *ret_vk) {

        _cleanup_(erase_and_freep) char *envpw = NULL;
        int r;

        assert_se(c);
        assert_se(c->node);
        assert_se(cd);
        assert_se(ret_vk);

        if (c->unlock_password) {
                r = sym_crypt_volume_key_get(
                                cd,
                                CRYPT_ANY_SLOT,
                                ret_vk->iov_base,
                                &ret_vk->iov_len,
                                c->unlock_password,
                                strlen(c->unlock_password));
                if (r < 0)
                        return log_error_errno(r, "Provided unlock password did not work: %m");

                return r;
        }

        r = getenv_steal_erase("PASSWORD", &envpw);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire password from environment: %m");
        if (r > 0) {
                r = sym_crypt_volume_key_get(
                                cd,
                                CRYPT_ANY_SLOT,
                                ret_vk->iov_base,
                                &ret_vk->iov_len,
                                envpw,
                                strlen(envpw));
                if (r < 0)
                        return log_error_errno(r, "Password from environment variable $PASSWORD did not work: %m");
        } else {
                AskPasswordFlags ask_password_flags = ASK_PASSWORD_PUSH_CACHE|ASK_PASSWORD_ACCEPT_CACHED;

                if (!c->interactive)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOPKG),
                                               "Password querying disabled via 'headless' option, but no password provided for disk %s.",
                                               c->node);
                _cleanup_free_ char *question = NULL, *id = NULL, *disk_path = NULL;
                unsigned i = 5;

                question = strjoin("Please enter current passphrase for disk ", c->node, ":");
                if (!question)
                        return log_oom();

                disk_path = cescape(c->node);
                if (!disk_path)
                        return log_oom();

                id = strjoin("cryptenroll:", disk_path);
                if (!id)
                        return log_oom();

                AskPasswordRequest req = {
                        .tty_fd = -EBADF,
                        .message = question,
                        .icon = "drive-harddisk",
                        .id = id,
                        .keyring = "cryptenroll",
                        .credential = "cryptenroll.passphrase",
                        .until = USEC_INFINITY,
                        .hup_fd = -EBADF,
                };

                for (;;) {
                        _cleanup_strv_free_erase_ char **passwords = NULL;

                        if (--i == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(ENOKEY),
                                                       "Too many attempts, giving up.");

                        r = ask_password_auto(&req, ask_password_flags, &passwords);
                        if (r < 0)
                                return log_error_errno(r, "Failed to query password: %m");

                        r = -EPERM;
                        STRV_FOREACH(p, passwords) {
                                r = sym_crypt_volume_key_get(
                                                cd,
                                                CRYPT_ANY_SLOT,
                                                ret_vk->iov_base,
                                                &ret_vk->iov_len,
                                                *p,
                                                strlen(*p));
                                if (r >= 0)
                                        break;
                        }
                        if (r >= 0)
                                break;

                        log_error_errno(r, "Password not correct, please try again: %m");
                        ask_password_flags &= ~ASK_PASSWORD_ACCEPT_CACHED;
                }
        }

        return r;
}

int enroll_password(
                const EnrollContext *c,
                struct crypt_device *cd,
                const struct iovec *volume_key) {

        _cleanup_(erase_and_freep) char *new_password = NULL;
        _cleanup_free_ char *error = NULL;
        const char *node;
        int r, keyslot;

        assert(c);
        assert(cd);
        assert(iovec_is_set(volume_key));

        assert_se(node = sym_crypt_get_device_name(cd));

        if (c->passphrase) {
                new_password = memdup_suffix0(c->passphrase, c->passphrase_size);
                if (!new_password)
                        return log_oom();
        } else {
                r = getenv_steal_erase("NEWPASSWORD", &new_password);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire password from environment: %m");
        }

        if (!new_password) {
                _cleanup_free_ char *disk_path = NULL, *id = NULL;
                unsigned i = 5;

                if (!c->interactive)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOPKG),
                                               "Password querying disabled via 'headless' option, but no new password provided.");

                assert_se(node = sym_crypt_get_device_name(cd));

                (void) suggest_passwords();

                disk_path = cescape(node);
                if (!disk_path)
                        return log_oom();

                id = strjoin("cryptenroll-new:", disk_path);
                if (!id)
                        return log_oom();

                AskPasswordRequest req = {
                        .tty_fd = -EBADF,
                        .icon = "drive-harddisk",
                        .id = id,
                        .keyring = "cryptenroll",
                        .credential = "cryptenroll.new-passphrase",
                        .until = USEC_INFINITY,
                        .hup_fd = -EBADF,
                };

                for (;;) {
                        _cleanup_strv_free_erase_ char **passwords = NULL, **passwords2 = NULL;
                        _cleanup_free_ char *question = NULL;

                        if (--i == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(ENOKEY),
                                                       "Too many attempts, giving up.");

                        question = strjoin("Please enter new passphrase for disk ", node, ":");
                        if (!question)
                                return log_oom();

                        req.message = question;

                        r = ask_password_auto(&req, /* flags= */ 0, &passwords);
                        if (r < 0)
                                return log_error_errno(r, "Failed to query password: %m");

                        assert(strv_length(passwords) == 1);

                        free(question);
                        question = strjoin("Please enter new passphrase for disk ", node, " (repeat):");
                        if (!question)
                                return log_oom();

                        req.message = question;

                        r = ask_password_auto(&req, /* flags= */ 0, &passwords2);
                        if (r < 0)
                                return log_error_errno(r, "Failed to query password: %m");

                        assert(strv_length(passwords2) == 1);

                        if (strv_equal(passwords, passwords2)) {
                                new_password = passwords2[0];
                                passwords2 = mfree(passwords2);
                                break;
                        }

                        log_error("Password didn't match, try again.");
                }
        }

        r = check_password_quality(new_password, /* old= */ NULL, /* user= */ NULL, &error);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                log_warning("Password quality check is not supported, proceeding anyway.");
        else if (r < 0)
                return log_error_errno(r, "Failed to check password quality: %m");
        else if (r == 0)
                log_warning("Specified password does not pass quality checks (%s), proceeding anyway.", error);

        keyslot = sym_crypt_keyslot_add_by_volume_key(
                        cd,
                        CRYPT_ANY_SLOT,
                        volume_key->iov_base,
                        volume_key->iov_len,
                        new_password,
                        strlen(new_password));
        if (keyslot < 0)
                return log_error_errno(keyslot, "Failed to add new password to %s: %m", node);

        log_info("New password enrolled as key slot %i.", keyslot);
        return keyslot;
}

int enroll_keyfile(
                const EnrollContext *c,
                struct crypt_device *cd,
                const struct iovec *volume_key) {

        _cleanup_(iovec_done_erase) struct iovec key = {};
        const char *node;
        int r, keyslot;

        assert(c);
        assert(c->keyfile);
        assert(cd);
        assert(iovec_is_set(volume_key));

        assert_se(node = sym_crypt_get_device_name(cd));

        r = read_full_file_full(
                        AT_FDCWD,
                        c->keyfile,
                        UINT64_MAX,
                        4U * U64_MB, /* safety net */
                        READ_FULL_FILE_SECURE|READ_FULL_FILE_WARN_WORLD_READABLE|READ_FULL_FILE_CONNECT_SOCKET|READ_FULL_FILE_FAIL_WHEN_LARGER,
                        NULL,
                        (char**) &key.iov_base,
                        &key.iov_len);
        if (r < 0)
                return log_error_errno(r, "Reading keyfile %s failed: %m", c->keyfile);
        if (key.iov_len == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Keyfile %s is empty, refusing. Use --empty to enroll an empty password.", c->keyfile);

        keyslot = sym_crypt_keyslot_add_by_volume_key(
                        cd,
                        CRYPT_ANY_SLOT,
                        volume_key->iov_base,
                        volume_key->iov_len,
                        key.iov_base,
                        key.iov_len);
        if (keyslot < 0)
                return log_error_errno(keyslot, "Failed to add keyfile to %s: %m", node);

        log_info("New keyfile enrolled as key slot %i.", keyslot);
        return keyslot;
}

int enroll_empty(
                const EnrollContext *c,
                struct crypt_device *cd,
                const struct iovec *volume_key) {

        const char *node;
        int r, keyslot;

        assert(c);
        assert(cd);
        assert(iovec_is_set(volume_key));

        assert_se(node = sym_crypt_get_device_name(cd));

        /* Key derivation cannot strengthen an empty password, hence don't waste time on it */
        r = cryptsetup_set_minimal_pbkdf(cd);
        if (r < 0)
                return log_error_errno(r, "Failed to set minimal PBKDF: %m");

        keyslot = sym_crypt_keyslot_add_by_volume_key(
                        cd,
                        CRYPT_ANY_SLOT,
                        volume_key->iov_base,
                        volume_key->iov_len,
                        "",
                        0);
        if (keyslot < 0)
                return log_error_errno(keyslot, "Failed to add empty password to %s: %m", node);

        log_info("New empty password enrolled as key slot %i.", keyslot);
        return keyslot;
}

static int find_active_volume(struct crypt_device *cd, char **ret_volume, dev_t *ret_devnum) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_free_ char *uuid = NULL, *pattern = NULL, *volume = NULL;
        dev_t devnum = 0;
        const char *u;
        int r;

        assert(cd);
        assert(ret_volume);
        assert(ret_devnum);

        /* Looks for an active dm-crypt mapping of the LUKS2 volume and returns its name. The DM UUID
         * cryptsetup assigns to such mappings is "CRYPT-LUKS2-<LUKS UUID without dashes>-<volume name>". */

        u = sym_crypt_get_uuid(cd);
        if (!u)
                return log_error_errno(SYNTHETIC_ERRNO(ENODATA), "LUKS2 volume has no UUID.");

        uuid = strdup(u);
        if (!uuid)
                return log_oom();
        delete_chars(uuid, "-");

        pattern = strjoin("CRYPT-LUKS2-", uuid, "-*");
        if (!pattern)
                return log_oom();

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate device enumerator: %m");

        r = sd_device_enumerator_add_match_subsystem(e, "block", /* match= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to add subsystem match: %m");

        r = sd_device_enumerator_add_match_property(e, "DM_UUID", pattern);
        if (r < 0)
                return log_error_errno(r, "Failed to add property match: %m");

        FOREACH_DEVICE(e, dev) {
                const char *name;

                r = sd_device_get_property_value(dev, "DM_NAME", &name);
                if (r < 0) {
                        log_device_debug_errno(dev, r, "Failed to get DM_NAME property, ignoring: %m");
                        continue;
                }

                if (volume)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ),
                                               "Multiple active mappings found for LUKS2 volume (%s, %s), please specify volume name explicitly.",
                                               volume, name);

                r = sd_device_get_devnum(dev, &devnum);
                if (r < 0)
                        return log_device_error_errno(dev, r, "Failed to get device number: %m");

                volume = strdup(name);
                if (!volume)
                        return log_oom();
        }

        if (!volume) {
                *ret_volume = NULL;
                *ret_devnum = 0;
                return 0;
        }

        *ret_volume = TAKE_PTR(volume);
        *ret_devnum = devnum;
        return 1;
}

int enroll_auto_keyfile(
                const EnrollContext *c,
                struct crypt_device *cd,
                const struct iovec *volume_key) {

        _cleanup_(iovec_done_erase) struct iovec key = {};
        _cleanup_free_ char *volume = NULL, *fn = NULL, *path = NULL;
        dev_t volume_devnum = 0;
        const char *node;
        int r, q, keyslot;

        assert(c);
        assert(cd);
        assert(iovec_is_set(volume_key));

        assert_se(node = sym_crypt_get_device_name(cd));

        /* systemd-cryptsetup looks for /etc/cryptsetup-keys.d/<volume>.key, where <volume> is the name the
         * volume is activated under (i.e. the first column in /etc/crypttab). */

        if (c->auto_keyfile_volume) {
                volume = strdup(c->auto_keyfile_volume);
                if (!volume)
                        return log_oom();
        } else {
                r = find_active_volume(cd, &volume, &volume_devnum);
                if (r < 0)
                        return r;
                if (r > 0)
                        log_info("Using name '%s' of active volume for keyfile.", volume);
                else {
                        const char *u = sym_crypt_get_uuid(cd);
                        if (!u)
                                return log_error_errno(SYNTHETIC_ERRNO(ENODATA), "LUKS2 volume has no UUID.");

                        volume = strjoin("luks-", u);
                        if (!volume)
                                return log_oom();

                        log_notice("Volume %s is not active, assuming it is activated as '%s'. "
                                   "Use --auto-keyfile=VOLUME to specify the volume name explicitly.",
                                   node, volume);
                }
        }

        fn = strjoin(volume, ".key");
        if (!fn)
                return log_oom();

        if (!filename_is_valid(fn))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Volume name '%s' is not suitable as keyfile name.", volume);

        path = path_join("/etc/cryptsetup-keys.d", fn);
        if (!path)
                return log_oom();

        if (access(path, F_OK) >= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EEXIST), "Keyfile %s already exists, refusing.", path);
        if (errno != ENOENT)
                return log_error_errno(errno, "Failed to check if %s exists: %m", path);

        if (volume_devnum != 0) {
                dev_t etc_devnum;

                r = get_block_device("/etc", &etc_devnum);
                if (r < 0)
                        log_debug_errno(r, "Failed to determine block device backing /etc/, ignoring: %m");
                else if (r > 0 && etc_devnum == volume_devnum)
                        log_warning("/etc/ is located on volume '%s' itself, the keyfile will not be accessible before the volume is unlocked.", volume);
        }

        r = crypto_random_bytes_allocate_iovec(AUTO_KEYFILE_SIZE, &key);
        if (r < 0)
                return log_error_errno(r, "Failed to generate keyfile: %m");

        /* The key has high entropy, hence key derivation would only slow down unlocking */
        r = cryptsetup_set_minimal_pbkdf(cd);
        if (r < 0)
                return log_error_errno(r, "Failed to set minimal PBKDF: %m");

        keyslot = sym_crypt_keyslot_add_by_volume_key(
                        cd,
                        CRYPT_ANY_SLOT,
                        volume_key->iov_base,
                        volume_key->iov_len,
                        key.iov_base,
                        key.iov_len);
        if (keyslot < 0)
                return log_error_errno(keyslot, "Failed to add keyfile to %s: %m", node);

        r = write_key_file(path, &key);
        if (r < 0) {
                q = sym_crypt_keyslot_destroy(cd, keyslot);
                if (q < 0)
                        log_debug_errno(q, "Unable to remove key slot we just added again, can't rollback, sorry: %m");

                return r;
        }

        log_info("New keyfile %s enrolled as key slot %i.", path, keyslot);
        return keyslot;
}
