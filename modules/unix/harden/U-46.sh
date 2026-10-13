#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_content.sh"

HARDEN_ITEM_ID='U-46'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-46.sh"
HARDEN_TARGET_DESCRIPTION='one static Sendmail PrivacyOptions assignment'
HARDEN_RISK_LEVEL='HIGH'
HARDEN_SERVICE_RELOAD_REQUIRED=true

u46_configuration_path=''

u46_require_fixture_policy() {
    if [ -z "$content_test_root" ] || \
        [ "$content_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        os_guard_content_set_error \
            'POLICY_INTEGRATION_REQUIRED' \
            'trusted U-46 operating policy integration is not available'
        return 1
    fi
    if [ "${OS_GUARD_TEST_APPROVED_MTA:-}" != 'sendmail' ] || \
        [ "${OS_GUARD_TEST_MAIL_EXECUTION_RESTRICTION_APPROVED:-false}" != 'true' ]; then
        os_guard_content_set_error \
            'MTA_POLICY_NOT_APPROVED' \
            'the fixture policy must approve Sendmail restrictqrun'
        return 1
    fi
    if [ "${OS_GUARD_TEST_SENDMAIL_CONFIGURATION_SOURCE:-}" != 'static-sendmail.cf' ]; then
        os_guard_content_set_error \
            'SENDMAIL_CONFIGURATION_SOURCE_UNVERIFIED' \
            'the fixture policy must verify sendmail.cf as the maintained source configuration'
        return 1
    fi
    if [ "${OS_GUARD_TEST_MAIL_QUEUE_IMPACT_VERIFIED:-false}" != 'true' ]; then
        os_guard_content_set_error \
            'MAIL_QUEUE_IMPACT_EVIDENCE_REQUIRED' \
            'mail queue and service-account impact evidence is required'
        return 1
    fi
    if [ "$content_action" = 'EXECUTE' ] && \
        [ "${OS_GUARD_TEST_RELOAD_APPROVED:-false}" != 'true' ]; then
        os_guard_content_set_error \
            'SERVICE_RELOAD_APPROVAL_REQUIRED' \
            'Sendmail reload approval is required before configuration mutation'
        return 1
    fi
    return 0
}

os_guard_item_validate_content_policy() {
    u46_require_fixture_policy
}

u46_privacy_options_count() {
    grep -Eic '^[[:space:]]*O[[:space:]]*PrivacyOptions[[:space:]]*=' "$1"
}

u46_privacy_option_present() {
    inspected_path=$1
    wanted_option=$2
    awk -v wanted="$wanted_option" '
        /^[[:space:]]*O[[:space:]]*PrivacyOptions[[:space:]]*=/ {
            line=$0
            sub(/#.*/, "", line)
            sub(/^[^=]*=/, "", line)
            count=split(line, options, ",")
            for (option_index=1; option_index<=count; option_index++) {
                option=tolower(options[option_index])
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", option)
                if (option == wanted) found=1
            }
        }
        END { exit found ? 0 : 1 }
    ' "$inspected_path"
}

os_guard_item_render_content() {
    source_path=$1
    awk '
        /^[[:space:]]*O[[:space:]]*PrivacyOptions[[:space:]]*=/ {
            rendered=$0
            if (tolower(rendered) !~ /(^|,)restrictqrun(,|[[:space:]#]|$)/) {
                comment=""
                comment_position=index(rendered, "#")
                if (comment_position > 0) {
                    comment=substr(rendered, comment_position)
                    rendered=substr(rendered, 1, comment_position - 1)
                    sub(/[[:space:]]+$/, "", rendered)
                }
                rendered=rendered ",restrictqrun"
                if (comment != "") rendered=rendered " " comment
            }
            print rendered
            next
        }
        { print }
    ' "$source_path"
}

os_guard_item_discover_content_targets() {
    u46_configuration_path="${content_test_root}/etc/mail/sendmail.cf"
    if [ ! -f "$u46_configuration_path" ] || [ -L "$u46_configuration_path" ]; then
        os_guard_content_set_error \
            'SUPPORTED_SENDMAIL_CONFIGURATION_REQUIRED' \
            'a regular Sendmail configuration file is required'
        return 1
    fi
    for generated_source in \
        "${content_test_root}/etc/mail/sendmail.mc" \
        "${content_test_root}/etc/mail/submit.mc"; do
        if [ -e "$generated_source" ] || [ -L "$generated_source" ]; then
            os_guard_content_set_error \
                'SENDMAIL_GENERATED_CONFIGURATION_UNSUPPORTED' \
                'sendmail.cf is generated from an available source configuration and is not edited directly'
            return 1
        fi
    done
    privacy_count=$(u46_privacy_options_count "$u46_configuration_path")
    if [ "$privacy_count" -ne 1 ]; then
        os_guard_content_set_error \
            'SENDMAIL_CONFIGURATION_AMBIGUOUS' \
            'exactly one static Sendmail PrivacyOptions assignment is required'
        return 1
    fi
    CONTENT_CURRENT_EFFECTIVE_VALUE='redacted Sendmail PrivacyOptions summary; see CHECK evidence'
    os_guard_content_add_target \
        "$u46_configuration_path" \
        '/etc/mail/sendmail.cf' \
        'PrivacyOptions' \
        'preserve existing options and add restrictqrun'
}

os_guard_item_validate_configuration() {
    if [ -n "$content_test_root" ] && \
        [ "${OS_GUARD_TEST_FORCE_ITEM_SYNTAX_FAILURE:-false}" = 'true' ]; then
        os_guard_content_set_error \
            'SENDMAIL_SYNTAX_VALIDATION_FAILED' \
            'forced Sendmail syntax validation failure'
        return 1
    fi
    if [ "$(u46_privacy_options_count "$u46_configuration_path")" -ne 1 ] || \
        ! u46_privacy_option_present "$u46_configuration_path" 'restrictqrun'; then
        os_guard_content_set_error \
            'SENDMAIL_SYNTAX_VALIDATION_FAILED' \
            'the resulting static PrivacyOptions assignment is invalid'
        return 1
    fi
    return 0
}

os_guard_content_run_module "${1:-}"
