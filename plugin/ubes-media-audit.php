<?php
/**
 * Plugin Name: UBES Media Audit
 * Description: Conservative media inventory, usage audit, quarantine/restore and bulk cleanup for the UBES WordPress site.
 * Version: 1.3.0
 * Author: UBES
 * Requires at least: 6.5
 * Requires PHP: 8.0
 */

if (!defined('ABSPATH')) {
    exit;
}

final class UBES_Media_Audit {
    const VERSION = '1.3.0';
    const MENU_SLUG = 'ubes-media-audit';
    const NONCE = 'ubes_media_audit_nonce';
    const STATE_OPTION = 'ubes_ma_scan_state';
    const FS_QUEUE_OPTION = 'ubes_ma_fs_queue';
    const DB_PLAN_OPTION = 'ubes_ma_db_plan';
    const CODE_QUEUE_OPTION = 'ubes_ma_code_queue';
    const FRONTEND_QUEUE_OPTION = 'ubes_ma_frontend_queue';
    const QUARANTINE_TOKEN_OPTION = 'ubes_ma_quarantine_token';

    private static $instance = null;
    private $items_table;
    private $aliases_table;
    private $refs_table;

    public static function instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        global $wpdb;
        $this->items_table   = $wpdb->prefix . 'ubes_media_audit_items';
        $this->aliases_table = $wpdb->prefix . 'ubes_media_audit_aliases';
        $this->refs_table    = $wpdb->prefix . 'ubes_media_audit_refs';

        add_action('admin_menu', [$this, 'admin_menu']);
        add_action('admin_enqueue_scripts', [$this, 'admin_assets']);

        add_action('wp_ajax_ubes_ma_scan_start', [$this, 'ajax_scan_start']);
        add_action('wp_ajax_ubes_ma_scan_step', [$this, 'ajax_scan_step']);

        add_action('admin_post_ubes_ma_bulk', [$this, 'handle_bulk']);
        add_action('admin_post_ubes_ma_export', [$this, 'handle_export']);
    }

    public static function activate() {
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $charset = $wpdb->get_charset_collate();
        $items = $wpdb->prefix . 'ubes_media_audit_items';
        $aliases = $wpdb->prefix . 'ubes_media_audit_aliases';
        $refs = $wpdb->prefix . 'ubes_media_audit_refs';

        $sql_items = "CREATE TABLE {$items} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            attachment_id BIGINT UNSIGNED NULL,
            rel_path TEXT NOT NULL,
            rel_hash CHAR(32) NOT NULL,
            file_name TEXT NOT NULL,
            mime_type VARCHAR(120) NOT NULL DEFAULT '',
            uploaded_at DATETIME NULL,
            modified_at DATETIME NULL,
            bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
            family_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
            width INT UNSIGNED NOT NULL DEFAULT 0,
            height INT UNSIGNED NOT NULL DEFAULT 0,
            is_orphan TINYINT(1) NOT NULL DEFAULT 0,
            parent_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            strong_refs INT UNSIGNED NOT NULL DEFAULT 0,
            weak_refs INT UNSIGNED NOT NULL DEFAULT 0,
            status VARCHAR(24) NOT NULL DEFAULT 'unknown',
            manual_keep TINYINT(1) NOT NULL DEFAULT 0,
            family_files LONGTEXT NULL,
            quarantine_data LONGTEXT NULL,
            last_scanned DATETIME NULL,
            PRIMARY KEY  (id),
            KEY attachment_id (attachment_id),
            KEY rel_hash (rel_hash),
            KEY status (status),
            KEY uploaded_at (uploaded_at),
            KEY manual_keep (manual_keep)
        ) {$charset};";

        $sql_aliases = "CREATE TABLE {$aliases} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            item_id BIGINT UNSIGNED NOT NULL,
            alias_hash CHAR(32) NOT NULL,
            alias_text TEXT NOT NULL,
            alias_kind VARCHAR(16) NOT NULL DEFAULT 'basename',
            PRIMARY KEY  (id),
            UNIQUE KEY item_alias (item_id, alias_hash, alias_kind),
            KEY alias_hash (alias_hash),
            KEY item_id (item_id)
        ) {$charset};";

        $sql_refs = "CREATE TABLE {$refs} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            item_id BIGINT UNSIGNED NOT NULL,
            strength VARCHAR(8) NOT NULL DEFAULT 'strong',
            source_type VARCHAR(16) NOT NULL DEFAULT 'database',
            source_table VARCHAR(191) NOT NULL DEFAULT '',
            source_key VARCHAR(191) NOT NULL DEFAULT '',
            source_detail TEXT NULL,
            matched_alias TEXT NULL,
            ref_hash CHAR(32) NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY ref_hash (ref_hash),
            KEY item_id (item_id),
            KEY strength (strength)
        ) {$charset};";

        dbDelta($sql_items);
        dbDelta($sql_aliases);
        dbDelta($sql_refs);

        if (!get_option(self::QUARANTINE_TOKEN_OPTION)) {
            add_option(self::QUARANTINE_TOKEN_OPTION, wp_generate_password(24, false, false), '', 'no');
        }
    }

    private function ensure_tables() {
        global $wpdb;
        $exists = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $this->items_table));
        if ($exists !== $this->items_table) {
            self::activate();
        }
    }

    public function admin_menu() {
        add_media_page(
            'UBES Media Audit',
            'Media Audit',
            'manage_options',
            self::MENU_SLUG,
            [$this, 'render_admin_page']
        );
    }

    public function admin_assets($hook) {
        if ($hook !== 'media_page_' . self::MENU_SLUG) {
            return;
        }

        wp_register_style('ubes-ma-admin', false, [], self::VERSION);
        wp_enqueue_style('ubes-ma-admin');
        wp_add_inline_style('ubes-ma-admin', $this->admin_css());

        wp_register_script('ubes-ma-admin', '', ['jquery'], self::VERSION, true);
        wp_enqueue_script('ubes-ma-admin');
        wp_localize_script('ubes-ma-admin', 'UBESMA', [
            'ajax' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce(self::NONCE),
            'pageUrl' => admin_url('upload.php?page=' . self::MENU_SLUG),
        ]);
        wp_add_inline_script('ubes-ma-admin', $this->admin_js());
    }

    private function admin_css() {
        return <<<'CSS'
.ubes-ma-wrap{max-width:1500px}.ubes-ma-hero{background:#fff;border:1px solid #dcdcde;border-radius:10px;padding:18px 20px;margin:16px 0;display:flex;gap:18px;align-items:center;justify-content:space-between;flex-wrap:wrap}.ubes-ma-hero h2{margin:0 0 5px}.ubes-ma-muted{color:#646970}.ubes-ma-stats{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}.ubes-ma-stat{background:#fff;border:1px solid #dcdcde;border-radius:8px;padding:10px 13px;min-width:125px}.ubes-ma-stat strong{display:block;font-size:19px}.ubes-ma-progress{display:none;margin-top:12px;min-width:360px;max-width:600px}.ubes-ma-progress-track{height:12px;background:#e8e8e8;border-radius:20px;overflow:hidden}.ubes-ma-progress-bar{height:100%;width:0;background:#2f5d50;transition:width .2s ease}.ubes-ma-progress-text{margin-top:6px;font-size:13px}.ubes-ma-filters{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:14px 0}.ubes-ma-table .column-cb{width:32px}.ubes-ma-thumb{width:56px;height:56px;border-radius:6px;object-fit:cover;background:#f0f0f1;border:1px solid #dcdcde}.ubes-ma-file{font-weight:600;word-break:break-all}.ubes-ma-path{font-size:11px;color:#72777c;word-break:break-all}.ubes-ma-badge{display:inline-block;padding:3px 8px;border-radius:999px;font-size:11px;font-weight:700;line-height:1.4}.ubes-ma-used{background:#e7f2ed;color:#24483f}.ubes-ma-candidate{background:#fff1cf;color:#6b4d00}.ubes-ma-keep{background:#e9eef5;color:#31445b}.ubes-ma-quarantined{background:#fce8e6;color:#8a2424}.ubes-ma-missing{background:#fce8e6;color:#8a2424}.ubes-ma-orphan{background:#f0f0f1;color:#50575e}.ubes-ma-ref-link{text-decoration:none}.ubes-ma-weak{color:#8a6d1d}.ubes-ma-detail{background:#fff;border:1px solid #dcdcde;border-radius:10px;padding:18px;margin:16px 0}.ubes-ma-detail-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin:12px 0}.ubes-ma-detail-grid>div{background:#f6f7f7;border-radius:6px;padding:9px}.ubes-ma-ref-table td{vertical-align:top}.ubes-ma-family{max-height:220px;overflow:auto;background:#f6f7f7;padding:10px;border-radius:6px;font-family:monospace;font-size:12px}.ubes-ma-danger{color:#b32d2e}.ubes-ma-toolbar{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}.ubes-ma-note{background:#fff8e5;border-left:4px solid #dba617;padding:10px 12px;margin:12px 0}.ubes-ma-good{background:#edf7ed;border-left:4px solid #2f5d50;padding:10px 12px;margin:12px 0}.ubes-ma-selection{display:none;background:#f0f6fc;border:1px solid #c5d9ed;border-top:0;padding:9px 12px;text-align:center}.ubes-ma-selection a{font-weight:600}.ubes-ma-selection strong{font-weight:700}@media(max-width:782px){.ubes-ma-progress{min-width:100%}.ubes-ma-hide-mobile{display:none}}
CSS;
    }

    private function admin_js() {
        return <<<'JS'
(function($){
    let running=false;
    function setProgress(p,msg){
        $('.ubes-ma-progress').show();
        $('.ubes-ma-progress-bar').css('width', Math.max(0,Math.min(100,p))+'%');
        $('.ubes-ma-progress-text').text(msg || 'Working…');
    }
    function step(){
        if(!running) return;
        $.post(UBESMA.ajax,{action:'ubes_ma_scan_step',nonce:UBESMA.nonce}).done(function(r){
            if(!r || !r.success){
                running=false;
                setProgress(0,(r && r.data && r.data.message) ? r.data.message : 'Scan failed.');
                return;
            }
            setProgress(r.data.progress || 0,r.data.message || 'Working…');
            if(r.data.done){
                running=false;
                setProgress(100,'Scan complete. Reloading…');
                setTimeout(function(){window.location=UBESMA.pageUrl;},650);
            } else {
                setTimeout(step,120);
            }
        }).fail(function(xhr){
            running=false;
            setProgress(0,'Scan request failed. '+(xhr.statusText || ''));
        });
    }
    $(document).on('click','#ubes-ma-start-scan',function(e){
        e.preventDefault();
        if(running) return;
        if(!confirm('Start a fresh full media audit? Existing non-quarantined scan results will be rebuilt. Quarantined files and restore manifests are preserved.')) return;
        $(this).prop('disabled',true);
        setProgress(1,'Starting scan…');
        $.post(UBESMA.ajax,{action:'ubes_ma_scan_start',nonce:UBESMA.nonce}).done(function(r){
            if(!r || !r.success){
                $('#ubes-ma-start-scan').prop('disabled',false);
                setProgress(0,(r && r.data && r.data.message) ? r.data.message : 'Could not start scan.');
                return;
            }
            running=true;
            step();
        }).fail(function(){
            $('#ubes-ma-start-scan').prop('disabled',false);
            setProgress(0,'Could not start scan.');
        });
    });
    function clearFilteredSelection(){
        $('#ubes-ma-selection-scope').val('page');
        $('.ubes-ma-selection').hide().removeClass('is-all');
        $('#ubes-ma-select-all-filtered').show();
        $('#ubes-ma-selection-message').text('');
    }
    function updateSelectionNotice(){
        let checked=$('.ubes-ma-row-check:checked').length;
        let visible=$('.ubes-ma-row-check').length;
        let total=parseInt($('#ubes-ma-bulk-form').data('filtered-total'),10)||visible;
        if(!checked){ clearFilteredSelection(); return; }
        if($('#ubes-ma-selection-scope').val()==='filtered'){
            $('.ubes-ma-selection').show().addClass('is-all');
            $('#ubes-ma-selection-message').html('<strong>All '+total+' items matching the current filters are selected.</strong>');
            $('#ubes-ma-select-all-filtered').hide();
            return;
        }
        if(checked===visible && total>visible){
            $('.ubes-ma-selection').show().removeClass('is-all');
            $('#ubes-ma-selection-message').text('All '+visible+' items on this page are selected.');
            $('#ubes-ma-select-all-filtered').text('Select all '+total+' items matching these filters').show();
        } else {
            $('.ubes-ma-selection').hide();
        }
    }
    $(document).on('change','#ubes-ma-check-all',function(){
        $('.ubes-ma-row-check').prop('checked',this.checked);
        clearFilteredSelection();
        updateSelectionNotice();
    });
    $(document).on('change','.ubes-ma-row-check',function(){
        if(!this.checked) clearFilteredSelection();
        let all=$('.ubes-ma-row-check').length && $('.ubes-ma-row-check:checked').length===$('.ubes-ma-row-check').length;
        $('#ubes-ma-check-all').prop('checked',all);
        updateSelectionNotice();
    });
    $(document).on('click','#ubes-ma-select-all-filtered',function(e){
        e.preventDefault();
        $('.ubes-ma-row-check,#ubes-ma-check-all').prop('checked',true);
        $('#ubes-ma-selection-scope').val('filtered');
        updateSelectionNotice();
    });
    $(document).on('click','#ubes-ma-clear-selection',function(e){
        e.preventDefault();
        $('.ubes-ma-row-check,#ubes-ma-check-all').prop('checked',false);
        clearFilteredSelection();
    });
    $(document).on('submit','#ubes-ma-bulk-form',function(e){
        let action=$('#ubes-ma-bulk-action').val();
        let filtered=$('#ubes-ma-selection-scope').val()==='filtered';
        let n=filtered ? (parseInt($(this).data('filtered-total'),10)||0) : $('.ubes-ma-row-check:checked').length;
        if(!action){e.preventDefault();alert('Choose a bulk action first.');return;}
        if(!n){e.preventDefault();alert('Select at least one media item.');return;}
        let scopeText=filtered ? ' matching the current filters' : '';
        if(action==='quarantine' && !confirm('Move '+n+' selected item(s)'+scopeText+' out of uploads into the reversible UBES quarantine? They will stop loading on the live site until restored.')){e.preventDefault();return;}
        if(action==='delete_permanently' && !confirm('PERMANENTLY delete '+n+' quarantined item(s)'+scopeText+'? This cannot be undone except from your external backup.')){e.preventDefault();return;}
    });
})(jQuery);
JS;
    }

    private function check_permissions_ajax() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'You do not have permission to run the media audit.'], 403);
        }
        check_ajax_referer(self::NONCE, 'nonce');
    }

    public function ajax_scan_start() {
        $this->check_permissions_ajax();
        $this->ensure_tables();
        global $wpdb;

        // Quarantined rows are deliberately preserved across rescans. This lets the
        // live-site pass discover whether a quarantined file is still referenced by a
        // rendered page, without destroying the restore manifest.
        $quarantined = (int)$wpdb->get_var("SELECT COUNT(*) FROM {$this->items_table} WHERE status='quarantined'");
        $keep_hashes = $wpdb->get_col("SELECT rel_hash FROM {$this->items_table} WHERE manual_keep=1");

        $wpdb->query("DELETE FROM {$this->refs_table}");
        $wpdb->query("DELETE a FROM {$this->aliases_table} a LEFT JOIN {$this->items_table} i ON i.id=a.item_id WHERE i.id IS NULL OR i.status<>'quarantined'");
        $wpdb->query("DELETE FROM {$this->items_table} WHERE status<>'quarantined'");

        delete_option(self::FS_QUEUE_OPTION);
        delete_option(self::DB_PLAN_OPTION);
        delete_option(self::CODE_QUEUE_OPTION);
        delete_option(self::FRONTEND_QUEUE_OPTION);

        $total_attachments = (int)$wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->posts} p WHERE p.post_type='attachment' AND NOT EXISTS (SELECT 1 FROM {$this->items_table} q WHERE q.status='quarantined' AND q.attachment_id=p.ID)");

        $state = [
            'stage' => 'attachments',
            'attachment_offset' => 0,
            'attachment_total' => $total_attachments,
            'fs_offset' => 0,
            'db_index' => 0,
            'db_offset' => 0,
            'frontend_offset' => 0,
            'frontend_total' => 0,
            'frontend_ok' => 0,
            'frontend_failed' => 0,
            'code_offset' => 0,
            'keep_hashes' => array_values(array_unique(array_map('strval', $keep_hashes ?: []))),
            'started' => time(),
        ];
        $this->set_nonautoload_option(self::STATE_OPTION, $state);

        wp_send_json_success(['message' => 'Scan started.']);
    }

    public function ajax_scan_step() {
        $this->check_permissions_ajax();
        $this->ensure_tables();

        $state = get_option(self::STATE_OPTION, []);
        if (!$state || empty($state['stage'])) {
            wp_send_json_error(['message' => 'No scan is currently running.']);
        }

        @set_time_limit(30);

        try {
            switch ($state['stage']) {
                case 'attachments':
                    $result = $this->scan_attachments_step($state);
                    break;
                case 'filesystem_prepare':
                    $result = $this->prepare_filesystem_step($state);
                    break;
                case 'filesystem':
                    $result = $this->scan_filesystem_step($state);
                    break;
                case 'database_prepare':
                    $result = $this->prepare_database_step($state);
                    break;
                case 'database':
                    $result = $this->scan_database_step($state);
                    break;
                case 'frontend_prepare':
                    $result = $this->prepare_frontend_step($state);
                    break;
                case 'frontend':
                    $result = $this->scan_frontend_step($state);
                    break;
                case 'code_prepare':
                    $result = $this->prepare_code_step($state);
                    break;
                case 'code':
                    $result = $this->scan_code_step($state);
                    break;
                case 'finalize':
                    $result = $this->finalize_scan($state);
                    break;
                default:
                    throw new Exception('Unknown scan stage: ' . sanitize_text_field($state['stage']));
            }
        } catch (Throwable $e) {
            wp_send_json_error(['message' => 'Scan stopped: ' . $e->getMessage()]);
        }

        $this->set_nonautoload_option(self::STATE_OPTION, $result['state']);
        wp_send_json_success([
            'done' => !empty($result['done']),
            'progress' => isset($result['progress']) ? (float)$result['progress'] : 0,
            'message' => $result['message'] ?? 'Working…',
        ]);
    }

    private function scan_attachments_step($state) {
        global $wpdb;
        $batch = 100;
        $offset = (int)$state['attachment_offset'];
        $ids = $wpdb->get_col($wpdb->prepare(
            "SELECT p.ID FROM {$wpdb->posts} p WHERE p.post_type='attachment' AND NOT EXISTS (SELECT 1 FROM {$this->items_table} q WHERE q.status='quarantined' AND q.attachment_id=p.ID) ORDER BY p.ID ASC LIMIT %d OFFSET %d",
            $batch,
            $offset
        ));

        foreach ($ids as $id) {
            $this->inventory_attachment((int)$id, $state['keep_hashes'] ?? []);
        }

        $offset += count($ids);
        $state['attachment_offset'] = $offset;
        $total = max(1, (int)$state['attachment_total']);
        $progress = min(25, ($offset / $total) * 25);

        if (count($ids) < $batch) {
            $state['stage'] = 'filesystem_prepare';
            $progress = 25;
            $message = 'Media Library inventoried. Preparing filesystem check…';
        } else {
            $message = 'Inventorying Media Library: ' . number_format(min($offset, $total)) . ' / ' . number_format($total);
        }

        return compact('state', 'progress', 'message') + ['done' => false];
    }

    private function inventory_attachment($attachment_id, $keep_hashes) {
        global $wpdb;
        $rel = get_post_meta($attachment_id, '_wp_attached_file', true);
        if (!is_string($rel) || $rel === '') {
            return;
        }

        $rel = $this->safe_rel_path($rel);
        if ($rel === '') {
            return;
        }

        $uploads = wp_get_upload_dir();
        $main_abs = $this->uploads_abs($rel);
        $post = get_post($attachment_id);
        if (!$post) {
            return;
        }

        $meta = wp_get_attachment_metadata($attachment_id);
        if (!is_array($meta)) {
            $meta = [];
        }

        $family = [$rel];
        $dir = dirname($rel);
        if ($dir === '.') {
            $dir = '';
        }

        if (!empty($meta['sizes']) && is_array($meta['sizes'])) {
            foreach ($meta['sizes'] as $size) {
                if (!empty($size['file'])) {
                    $family[] = ltrim(($dir ? $dir . '/' : '') . $size['file'], '/');
                }
            }
        }
        if (!empty($meta['original_image'])) {
            $family[] = ltrim(($dir ? $dir . '/' : '') . $meta['original_image'], '/');
        }

        $backup_sizes = get_post_meta($attachment_id, '_wp_attachment_backup_sizes', true);
        if (is_array($backup_sizes)) {
            foreach ($backup_sizes as $size) {
                if (!empty($size['file'])) {
                    $family[] = ltrim(($dir ? $dir . '/' : '') . $size['file'], '/');
                }
            }
        }

        $family = array_values(array_unique(array_filter(array_map([$this, 'safe_rel_path'], $family))));

        $main_bytes = (is_file($main_abs) && is_readable($main_abs)) ? (int)@filesize($main_abs) : 0;
        $family_bytes = 0;
        $latest_mtime = 0;
        foreach ($family as $f) {
            $abs = $this->uploads_abs($f);
            if (is_file($abs)) {
                $family_bytes += (int)@filesize($abs);
                $latest_mtime = max($latest_mtime, (int)@filemtime($abs));
            }
        }

        $width = !empty($meta['width']) ? (int)$meta['width'] : 0;
        $height = !empty($meta['height']) ? (int)$meta['height'] : 0;
        $rel_hash = md5(strtolower($rel));
        $manual_keep = in_array($rel_hash, $keep_hashes, true) ? 1 : 0;

        $wpdb->insert($this->items_table, [
            'attachment_id' => $attachment_id,
            'rel_path' => $rel,
            'rel_hash' => $rel_hash,
            'file_name' => basename($rel),
            'mime_type' => (string)$post->post_mime_type,
            'uploaded_at' => $post->post_date ?: null,
            'modified_at' => $latest_mtime ? gmdate('Y-m-d H:i:s', $latest_mtime) : null,
            'bytes' => $main_bytes,
            'family_bytes' => $family_bytes,
            'width' => $width,
            'height' => $height,
            'is_orphan' => 0,
            'parent_id' => (int)$post->post_parent,
            'status' => $manual_keep ? 'keep' : ($main_bytes ? 'unknown' : 'missing'),
            'manual_keep' => $manual_keep,
            'family_files' => wp_json_encode($family),
            'last_scanned' => current_time('mysql'),
        ]);

        $item_id = (int)$wpdb->insert_id;
        if (!$item_id) {
            return;
        }
        foreach ($family as $f) {
            $this->add_alias($item_id, $f, 'path');
            $this->add_alias($item_id, basename($f), 'basename');
        }

        // A Media Library attachment explicitly attached to a live WordPress post is
        // protected. This is especially important for custom content types such as the
        // UBES Route Logbook, where GPX/photos can be attached via post_parent even
        // when the filename is not present in ordinary page content.
        if ((int)$post->post_parent > 0) {
            $parent = get_post((int)$post->post_parent);
            if ($parent && $parent->post_type !== 'revision' && !in_array($parent->post_status, ['trash', 'auto-draft'], true)) {
                $detail = sprintf('Attached to post #%d: %s [%s / %s]', (int)$parent->ID, trim(wp_strip_all_tags((string)$parent->post_title)), (string)$parent->post_type, (string)$parent->post_status);
                $this->insert_ref($item_id, 'strong', 'parent', $wpdb->posts, (string)$parent->ID, $detail, 'attachment parent');
            }
        }
    }

    private function prepare_filesystem_step($state) {
        $uploads = wp_get_upload_dir();
        $base = wp_normalize_path($uploads['basedir']);
        $files = [];

        if (is_dir($base)) {
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::LEAVES_ONLY
            );
            foreach ($it as $file) {
                if (!$file->isFile()) {
                    continue;
                }
                $abs = wp_normalize_path($file->getPathname());
                if (strpos($abs, $base . '/') !== 0) {
                    continue;
                }
                $rel = ltrim(substr($abs, strlen($base)), '/');
                if (!$this->is_auditable_upload_path($rel)) {
                    continue;
                }
                $files[] = $rel;
            }
        }

        sort($files, SORT_NATURAL | SORT_FLAG_CASE);
        $this->set_nonautoload_option(self::FS_QUEUE_OPTION, $files);
        $state['stage'] = 'filesystem';
        $state['fs_offset'] = 0;
        $state['fs_total'] = count($files);

        return [
            'state' => $state,
            'progress' => 26,
            'message' => 'Filesystem list prepared: ' . number_format(count($files)) . ' files in normal uploads folders.',
            'done' => false,
        ];
    }

    private function scan_filesystem_step($state) {
        global $wpdb;
        $queue = get_option(self::FS_QUEUE_OPTION, []);
        $batch = 500;
        $offset = (int)$state['fs_offset'];
        $slice = array_slice($queue, $offset, $batch);

        if ($slice) {
            $norm_to_rel = [];
            $hashes = [];
            foreach ($slice as $rel) {
                $norm = $this->normalize_alias($rel);
                if ($norm === '') continue;
                $norm_to_rel[$norm] = $rel;
                $hashes[] = md5($norm);
            }
            $known = [];
            if ($hashes) {
                $placeholders = implode(',', array_fill(0, count($hashes), '%s'));
                $sql = $wpdb->prepare("SELECT alias_hash, alias_text FROM {$this->aliases_table} WHERE alias_hash IN ({$placeholders})", $hashes);
                foreach ($wpdb->get_results($sql) as $row) {
                    $known[$row->alias_hash . '|' . $row->alias_text] = true;
                }
            }

            foreach ($norm_to_rel as $norm => $rel) {
                $key = md5($norm) . '|' . $norm;
                if (isset($known[$key])) {
                    continue;
                }
                $this->inventory_orphan($rel, $state['keep_hashes'] ?? []);
            }
        }

        $offset += count($slice);
        $state['fs_offset'] = $offset;
        $total = max(1, (int)($state['fs_total'] ?? count($queue)));
        $progress = 26 + min(14, ($offset / $total) * 14);

        if (count($slice) < $batch) {
            delete_option(self::FS_QUEUE_OPTION);
            $state['stage'] = 'database_prepare';
            $progress = 40;
            $message = 'Filesystem inventory complete. Preparing database reference scan…';
        } else {
            $message = 'Checking uploads filesystem: ' . number_format(min($offset, $total)) . ' / ' . number_format($total);
        }

        return compact('state', 'progress', 'message') + ['done' => false];
    }

    private function inventory_orphan($rel, $keep_hashes) {
        global $wpdb;
        $rel = $this->safe_rel_path($rel);
        if ($rel === '') return;
        $abs = $this->uploads_abs($rel);
        if (!is_file($abs)) return;

        $size = (int)@filesize($abs);
        $mtime = (int)@filemtime($abs);
        $type = wp_check_filetype($rel);
        $mime = $type['type'] ?? '';
        $width = 0;
        $height = 0;
        if ($mime && strpos($mime, 'image/') === 0) {
            $img = @getimagesize($abs);
            if (is_array($img)) {
                $width = (int)$img[0];
                $height = (int)$img[1];
            }
        }

        $rel_hash = md5(strtolower($rel));
        $manual_keep = in_array($rel_hash, $keep_hashes, true) ? 1 : 0;

        $wpdb->insert($this->items_table, [
            'attachment_id' => null,
            'rel_path' => $rel,
            'rel_hash' => $rel_hash,
            'file_name' => basename($rel),
            'mime_type' => (string)$mime,
            'uploaded_at' => $mtime ? gmdate('Y-m-d H:i:s', $mtime) : null,
            'modified_at' => $mtime ? gmdate('Y-m-d H:i:s', $mtime) : null,
            'bytes' => $size,
            'family_bytes' => $size,
            'width' => $width,
            'height' => $height,
            'is_orphan' => 1,
            'parent_id' => 0,
            'status' => $manual_keep ? 'keep' : 'unknown',
            'manual_keep' => $manual_keep,
            'family_files' => wp_json_encode([$rel]),
            'last_scanned' => current_time('mysql'),
        ]);
        $item_id = (int)$wpdb->insert_id;
        if ($item_id) {
            $this->add_alias($item_id, $rel, 'path');
            $this->add_alias($item_id, basename($rel), 'basename');
        }
    }

    private function prepare_database_step($state) {
        global $wpdb;
        $like = $wpdb->esc_like($wpdb->prefix) . '%';
        $tables = $wpdb->get_col($wpdb->prepare('SHOW TABLES LIKE %s', $like));
        $plan = [];

        foreach ($tables as $table) {
            if (in_array($table, [$this->items_table, $this->aliases_table, $this->refs_table], true)) {
                continue;
            }
            if (strpos($table, $wpdb->prefix . 'mclean_') === 0) {
                continue; // Media Cleaner analysis tables are not usage references.
            }

            $cols = $wpdb->get_results('SHOW COLUMNS FROM ' . $this->qi($table));
            if (!$cols) continue;
            $text_cols = [];
            $id_cols = [];
            $pk = '';
            foreach ($cols as $c) {
                if ($c->Key === 'PRI' && $pk === '') {
                    $pk = $c->Field;
                }
                if (preg_match('/char|text|json|enum|set/i', (string)$c->Type)) {
                    $text_cols[] = $c->Field;
                }
                if (preg_match('/(?:attachment|image|media|photo|thumbnail)[_-]?(?:id|ids)$/i', (string)$c->Field) && preg_match('/int|decimal|numeric|char|text/i', (string)$c->Type)) {
                    $id_cols[] = $c->Field;
                }
            }
            if (!$text_cols && !$id_cols) continue;

            // Fast conservative scan: ignore logs/caches/history entirely because they
            // cannot make an item "Used". Scan core content/config tables plus custom
            // tables that are plausibly capable of storing live media references.
            if ($this->should_skip_database_table($table)) {
                continue;
            }
            if (!$this->is_sensible_database_table($table, $id_cols)) {
                continue;
            }

            $plan[] = [
                'table' => $table,
                'text_cols' => array_values(array_unique($text_cols)),
                'id_cols' => array_values(array_unique($id_cols)),
                'pk' => $pk,
            ];
        }

        $this->set_nonautoload_option(self::DB_PLAN_OPTION, $plan);
        $state['stage'] = 'database';
        $state['db_index'] = 0;
        $state['db_offset'] = 0;
        $state['db_total_tables'] = count($plan);

        return [
            'state' => $state,
            'progress' => 41,
            'message' => 'Fast database scan prepared: ' . number_format(count($plan)) . ' content-bearing tables.',
            'done' => false,
        ];
    }

    private function scan_database_step($state) {
        global $wpdb;
        $plan = get_option(self::DB_PLAN_OPTION, []);
        $index = (int)$state['db_index'];
        $offset = (int)$state['db_offset'];
        $batch = 500;
        $total_tables = max(1, count($plan));

        if ($index >= count($plan)) {
            delete_option(self::DB_PLAN_OPTION);
            $state['stage'] = 'frontend_prepare';
            return [
                'state' => $state,
                'progress' => 70,
                'message' => 'Database reference scan complete. Preparing rendered-site scan…',
                'done' => false,
            ];
        }

        $spec = $plan[$index];
        $table = $spec['table'];
        $selected = $spec['text_cols'];
        if (!empty($spec['id_cols'])) $selected = array_merge($selected, $spec['id_cols']);
        if (!empty($spec['pk'])) $selected[] = $spec['pk'];

        // Special fields used to avoid self-references and label results.
        if ($table === $wpdb->posts) {
            $selected = array_merge($selected, ['ID', 'post_type', 'post_status', 'post_title']);
        } elseif ($table === $wpdb->postmeta) {
            $selected = array_merge($selected, ['meta_id', 'post_id', 'meta_key', 'meta_value']);
        } elseif ($table === $wpdb->options) {
            $selected = array_merge($selected, ['option_id', 'option_name', 'option_value']);
        }
        $selected = array_values(array_unique($selected));

        $cols_sql = implode(', ', array_map([$this, 'qi'], $selected));
        $sql = 'SELECT ' . $cols_sql . ' FROM ' . $this->qi($table) . $wpdb->prepare(' LIMIT %d OFFSET %d', $batch, $offset);
        $rows = $wpdb->get_results($sql, ARRAY_A);

        foreach ($rows as $row) {
            if ($table === $wpdb->posts && (($row['post_type'] ?? '') === 'attachment')) {
                continue;
            }
            if ($table === $wpdb->postmeta && in_array((string)($row['meta_key'] ?? ''), ['_wp_attached_file', '_wp_attachment_metadata', '_wp_attachment_backup_sizes'], true)) {
                continue;
            }

            $strength = $this->database_reference_strength($table, $row);
            $text_parts = [];
            foreach ($spec['text_cols'] as $col) {
                if (isset($row[$col]) && is_scalar($row[$col]) && $row[$col] !== '') {
                    $text_parts[] = (string)$row[$col];
                }
            }
            $text = implode("\n", $text_parts);
            $source_key = $this->source_key_for_row($spec, $row, $offset);
            $source_detail = $this->source_detail_for_row($table, $row, $source_key);

            // Numeric/custom-table media ID columns.
            if (!empty($spec['id_cols'])) {
                foreach ($spec['id_cols'] as $id_col) {
                    if (!isset($row[$id_col])) continue;
                    $raw_ids = preg_split('/[^0-9]+/', (string)$row[$id_col], -1, PREG_SPLIT_NO_EMPTY);
                    if ($raw_ids) {
                        $this->add_attachment_id_refs(array_map('intval', $raw_ids), $strength, 'database', $table, $source_key, $source_detail, $id_col);
                    }
                }
            }

            // Core featured image reference is ID-only.
            if ($table === $wpdb->postmeta && ($row['meta_key'] ?? '') === '_thumbnail_id' && ctype_digit((string)($row['meta_value'] ?? ''))) {
                $this->add_attachment_id_refs([(int)$row['meta_value']], $strength, 'database', $table, $source_key, $source_detail, '_thumbnail_id');
            }

            // Custom plugins commonly store attachment IDs in post meta under keys
            // such as gpx_id, route_photos, gallery_ids, file, image, etc. Parse the
            // numeric values only when the meta key itself is media-shaped; IDs are
            // then validated against actual Media Library attachment IDs.
            if ($table === $wpdb->postmeta) {
                $meta_key = strtolower((string)($row['meta_key'] ?? ''));
                $meta_value = (string)($row['meta_value'] ?? '');
                if ($this->meta_key_can_reference_media($meta_key) && $meta_value !== '') {
                    $raw_ids = preg_split('/[^0-9]+/', $meta_value, -1, PREG_SPLIT_NO_EMPTY);
                    if ($raw_ids) {
                        $this->add_attachment_id_refs(array_map('intval', $raw_ids), $strength, 'database', $table, $source_key, $source_detail, 'media meta ' . $meta_key);
                    }
                }
            }

            $tokens = $text !== '' ? $this->extract_media_tokens($text) : [];
            if ($tokens) {
                $this->add_token_refs($tokens, $strength, 'database', $table, $source_key, $source_detail);
            }

            $ids = $text !== '' ? $this->extract_attachment_ids($text) : [];
            if ($ids) {
                $this->add_attachment_id_refs($ids, $strength, 'database', $table, $source_key, $source_detail, 'attachment ID');
            }
        }

        if (count($rows) < $batch) {
            $index++;
            $offset = 0;
        } else {
            $offset += count($rows);
        }

        $state['db_index'] = $index;
        $state['db_offset'] = $offset;
        $progress = 41 + min(29, ($index / $total_tables) * 29);
        $message = 'Scanning database references: table ' . min($index + 1, $total_tables) . ' / ' . $total_tables . ' (' . $table . ')';

        return compact('state', 'progress', 'message') + ['done' => false];
    }

    private function prepare_frontend_step($state) {
        global $wpdb;
        $urls = [home_url('/')];

        // Crawl actual rendered public content. This catches theme widgets, shortcode
        // output, Optimizer/theme settings and custom plugins even when their media
        // references are stored in a format that a database token scan cannot infer.
        $post_types = get_post_types(['public' => true], 'names');
        unset($post_types['attachment']);
        $post_types = array_values(array_unique(array_filter($post_types)));

        if ($post_types) {
            $placeholders = implode(',', array_fill(0, count($post_types), '%s'));
            $sql = $wpdb->prepare(
                "SELECT ID FROM {$wpdb->posts} WHERE post_status='publish' AND post_type IN ({$placeholders}) ORDER BY ID ASC",
                $post_types
            );
            foreach ($wpdb->get_col($sql) as $post_id) {
                $url = get_permalink((int)$post_id);
                if (is_string($url) && $url !== '') $urls[] = $url;
            }
        }

        // Include the posts page / static front page explicitly, plus any public CPT
        // archive URLs. They can contain theme/widget assets not present on a single.
        foreach (['page_on_front', 'page_for_posts'] as $opt) {
            $id = (int)get_option($opt);
            if ($id > 0) {
                $url = get_permalink($id);
                if ($url) $urls[] = $url;
            }
        }
        foreach (get_post_types(['public' => true, 'has_archive' => true], 'objects') as $obj) {
            if ($obj->name === 'attachment') continue;
            $url = get_post_type_archive_link($obj->name);
            if ($url) $urls[] = $url;
        }

        $urls = array_values(array_unique(array_filter(array_map('esc_url_raw', $urls))));
        $this->set_nonautoload_option(self::FRONTEND_QUEUE_OPTION, $urls);
        $state['stage'] = 'frontend';
        $state['frontend_offset'] = 0;
        $state['frontend_total'] = count($urls);
        $state['frontend_ok'] = 0;
        $state['frontend_failed'] = 0;

        return [
            'state' => $state,
            'progress' => 71,
            'message' => 'Rendered-site scan prepared: ' . number_format(count($urls)) . ' public URLs.',
            'done' => false,
        ];
    }

    private function scan_frontend_step($state) {
        $queue = get_option(self::FRONTEND_QUEUE_OPTION, []);
        $offset = (int)($state['frontend_offset'] ?? 0);
        $batch = 5;
        $slice = array_slice($queue, $offset, $batch);

        foreach ($slice as $url) {
            $response = wp_remote_get($url, [
                'timeout' => 5,
                'redirection' => 3,
                'user-agent' => 'UBES-Media-Audit/' . self::VERSION . '; ' . home_url('/'),
                'headers' => ['Cache-Control' => 'no-cache'],
                'limit_response_size' => 5 * 1024 * 1024,
            ]);

            if (is_wp_error($response)) {
                $state['frontend_failed'] = (int)($state['frontend_failed'] ?? 0) + 1;
                continue;
            }
            $code = (int)wp_remote_retrieve_response_code($response);
            $body = (string)wp_remote_retrieve_body($response);
            if ($code < 200 || $code >= 400 || $body === '') {
                $state['frontend_failed'] = (int)($state['frontend_failed'] ?? 0) + 1;
                continue;
            }

            $state['frontend_ok'] = (int)($state['frontend_ok'] ?? 0) + 1;
            $detail = 'Rendered page: ' . $url;
            $tokens = $this->extract_media_tokens($body);
            if ($tokens) {
                $this->add_token_refs($tokens, 'strong', 'frontend', '', md5($url), $detail);
            }
            $ids = $this->extract_attachment_ids($body);
            if ($ids) {
                $this->add_attachment_id_refs($ids, 'strong', 'frontend', '', md5($url), $detail, 'rendered attachment ID');
            }
        }

        $offset += count($slice);
        $state['frontend_offset'] = $offset;
        $total = max(1, (int)($state['frontend_total'] ?? count($queue)));
        $progress = 71 + min(15, ($offset / $total) * 15);

        if (count($slice) < $batch) {
            delete_option(self::FRONTEND_QUEUE_OPTION);
            $state['stage'] = 'code_prepare';
            $progress = 86;
            $message = sprintf(
                'Rendered-site scan complete: %s pages checked%s. Preparing code scan…',
                number_format((int)($state['frontend_ok'] ?? 0)),
                ((int)($state['frontend_failed'] ?? 0) > 0) ? ', ' . number_format((int)$state['frontend_failed']) . ' failed' : ''
            );
        } else {
            $message = 'Checking rendered public pages: ' . number_format(min($offset, $total)) . ' / ' . number_format($total);
        }

        return compact('state', 'progress', 'message') + ['done' => false];
    }

    private function prepare_code_step($state) {
        $files = [];
        $roots = [];

        $stylesheet = get_stylesheet_directory();
        $template = get_template_directory();
        if ($stylesheet && is_dir($stylesheet)) $roots[] = $stylesheet;
        if ($template && is_dir($template) && wp_normalize_path($template) !== wp_normalize_path($stylesheet)) $roots[] = $template;

        $active = (array)get_option('active_plugins', []);
        foreach ($active as $plugin_file) {
            $abs = WP_PLUGIN_DIR . '/' . ltrim($plugin_file, '/');
            if (!is_file($abs)) continue;

            // Always inspect the active plugin bootstrap file. Recursively scan only
            // site-specific/custom-looking plugins; third-party vendor source cannot
            // normally contain hard-coded references to this site's uploads and was a
            // major source of wasted scan time in v1.0.
            $files[] = wp_normalize_path($abs);
            $slug = strtolower(dirname($plugin_file) . '/' . basename($plugin_file));
            if (preg_match('/(?:ubes|route|logbook|custom|snippet)/i', $slug)) {
                $dir = dirname($abs);
                if ($dir !== wp_normalize_path(WP_PLUGIN_DIR)) $roots[] = $dir;
            }
        }
        if (defined('WPMU_PLUGIN_DIR') && is_dir(WPMU_PLUGIN_DIR)) {
            $roots[] = WPMU_PLUGIN_DIR;
        }

        $roots = array_values(array_unique(array_map('wp_normalize_path', $roots)));
        foreach ($roots as $root) {
            $this->collect_code_files($root, $files);
        }
        $files = array_values(array_unique($files));
        sort($files, SORT_NATURAL | SORT_FLAG_CASE);

        $this->set_nonautoload_option(self::CODE_QUEUE_OPTION, $files);
        $state['stage'] = 'code';
        $state['code_offset'] = 0;
        $state['code_total'] = count($files);

        return [
            'state' => $state,
            'progress' => 86,
            'message' => 'Code scan prepared: ' . number_format(count($files)) . ' relevant theme/custom-plugin files.',
            'done' => false,
        ];
    }

    private function scan_code_step($state) {
        $queue = get_option(self::CODE_QUEUE_OPTION, []);
        $batch = 80;
        $offset = (int)$state['code_offset'];
        $slice = array_slice($queue, $offset, $batch);

        foreach ($slice as $file) {
            if (!is_file($file) || !is_readable($file)) continue;
            $size = (int)@filesize($file);
            if ($size <= 0 || $size > 2 * 1024 * 1024) continue;
            $text = @file_get_contents($file);
            if (!is_string($text) || $text === '') continue;
            $tokens = $this->extract_media_tokens($text);
            if (!$tokens) continue;

            $detail = $this->code_file_label($file);
            $this->add_token_refs($tokens, 'strong', 'code', '', $detail, $detail);
        }

        $offset += count($slice);
        $state['code_offset'] = $offset;
        $total = max(1, (int)($state['code_total'] ?? count($queue)));
        $progress = 86 + min(12, ($offset / $total) * 12);

        if (count($slice) < $batch) {
            delete_option(self::CODE_QUEUE_OPTION);
            $state['stage'] = 'finalize';
            $progress = 98;
            $message = 'Code reference scan complete. Finalising results…';
        } else {
            $message = 'Scanning active theme/plugin code: ' . number_format(min($offset, $total)) . ' / ' . number_format($total);
        }
        return compact('state', 'progress', 'message') + ['done' => false];
    }

    private function finalize_scan($state) {
        global $wpdb;

        $wpdb->query("UPDATE {$this->items_table} SET strong_refs=0, weak_refs=0");
        $strong = $wpdb->get_results("SELECT item_id, COUNT(*) c FROM {$this->refs_table} WHERE strength='strong' GROUP BY item_id");
        foreach ($strong as $r) {
            $wpdb->update($this->items_table, ['strong_refs' => (int)$r->c], ['id' => (int)$r->item_id]);
        }
        $weak = $wpdb->get_results("SELECT item_id, COUNT(*) c FROM {$this->refs_table} WHERE strength='weak' GROUP BY item_id");
        foreach ($weak as $r) {
            $wpdb->update($this->items_table, ['weak_refs' => (int)$r->c], ['id' => (int)$r->item_id]);
        }

        $rows = $wpdb->get_results("SELECT id, rel_path, attachment_id, manual_keep, strong_refs, status FROM {$this->items_table}");
        foreach ($rows as $r) {
            if ((string)$r->status === 'quarantined') {
                // Never overwrite quarantine state during a rescan. Reference counts
                // are still refreshed, so a quarantined-but-used file is obvious.
                $wpdb->update($this->items_table, ['last_scanned' => current_time('mysql')], ['id' => (int)$r->id]);
                continue;
            }
            if ((int)$r->manual_keep === 1) {
                $status = 'keep';
            } elseif ($r->attachment_id && !is_file($this->uploads_abs($r->rel_path))) {
                $status = 'missing';
            } elseif ((int)$r->strong_refs > 0) {
                $status = 'used';
            } else {
                $status = 'candidate';
            }
            $wpdb->update($this->items_table, ['status' => $status, 'last_scanned' => current_time('mysql')], ['id' => (int)$r->id]);
        }

        $state['stage'] = 'complete';
        $state['completed'] = time();
        delete_option(self::FS_QUEUE_OPTION);
        delete_option(self::DB_PLAN_OPTION);
        delete_option(self::CODE_QUEUE_OPTION);
        delete_option(self::FRONTEND_QUEUE_OPTION);

        return [
            'state' => $state,
            'progress' => 100,
            'message' => 'Media audit complete.',
            'done' => true,
        ];
    }

    private function collect_code_files($root, &$files) {
        $root = wp_normalize_path($root);
        if (!is_dir($root)) return;
        $allowed = ['php','css','js','json','html','htm','txt','xml'];
        $skip_dirs = ['node_modules','vendor','.git','cache','languages','tests','test'];
        try {
            $it = new RecursiveIteratorIterator(
                new RecursiveCallbackFilterIterator(
                    new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
                    function($current) use ($skip_dirs) {
                        if ($current->isDir()) {
                            return !in_array(strtolower($current->getFilename()), $skip_dirs, true);
                        }
                        return true;
                    }
                ),
                RecursiveIteratorIterator::LEAVES_ONLY
            );
            foreach ($it as $file) {
                if (!$file->isFile()) continue;
                $ext = strtolower(pathinfo($file->getFilename(), PATHINFO_EXTENSION));
                if (!in_array($ext, $allowed, true)) continue;
                if ((int)$file->getSize() > 2 * 1024 * 1024) continue;
                $files[] = wp_normalize_path($file->getPathname());
            }
        } catch (Throwable $e) {
            // A single unreadable plugin directory should not stop the audit.
        }
    }

    private function code_file_label($file) {
        $file = wp_normalize_path($file);
        $content = wp_normalize_path(WP_CONTENT_DIR);
        if (strpos($file, $content . '/') === 0) {
            return 'wp-content/' . ltrim(substr($file, strlen($content)), '/');
        }
        return basename($file);
    }

    private function should_skip_database_table($table) {
        $t = strtolower((string)$table);
        $markers = [
            'log', 'cache', 'history', 'analytics', 'click', 'event', 'session', 'queue',
            'audit', 'occurrence', 'visitor', 'stat', 'hit', 'view', 'backup', 'indexable',
            'seo_links', 'completed_jobs', 'failed_jobs', 'feed_cache', 'resque',
            'action_scheduler', 'actionscheduler', 'transient'
        ];
        foreach ($markers as $marker) {
            if (strpos($t, $marker) !== false) return true;
        }
        return false;
    }

    private function is_sensible_database_table($table, $id_cols = []) {
        global $wpdb;
        $core = [
            $wpdb->posts,
            $wpdb->postmeta,
            $wpdb->options,
            $wpdb->termmeta,
            $wpdb->usermeta,
        ];
        if (in_array($table, $core, true)) return true;
        if (!empty($id_cols)) return true;

        $short = strtolower((string)$table);
        if (strpos($short, strtolower($wpdb->prefix)) === 0) {
            $short = substr($short, strlen($wpdb->prefix));
        }
        return (bool)preg_match('/(?:media|image|photo|gallery|route|gpx|attachment|upload|file|slide|banner|content|form|widget|setting|option|meta|snippet)/i', $short);
    }

    private function meta_key_can_reference_media($key) {
        $key = strtolower((string)$key);
        if ($key === '') return false;
        return (bool)preg_match('/(?:attachment|image|media|photo|thumbnail|file|gpx|gallery|route|download|document|pdf)/i', $key);
    }

    private function database_reference_strength($table, $row) {
        $t = strtolower($table);
        $weak_markers = [
            'log', 'cache', 'history', 'analytics', 'click', 'event', 'session', 'queue',
            'audit', 'occurrence', 'visitor', 'stat', 'hit', 'view', 'backup', 'indexable',
            'seo_links', 'completed_jobs', 'failed_jobs', 'feed_cache'
        ];
        foreach ($weak_markers as $marker) {
            if (strpos($t, $marker) !== false) return 'weak';
        }

        global $wpdb;
        if ($table === $wpdb->posts) {
            $status = (string)($row['post_status'] ?? '');
            $type = (string)($row['post_type'] ?? '');
            if ($type === 'revision' || in_array($status, ['trash', 'auto-draft'], true)) return 'weak';
        }
        if ($table === $wpdb->options) {
            $name = (string)($row['option_name'] ?? '');
            if (strpos($name, '_transient_') === 0 || strpos($name, '_site_transient_') === 0) return 'weak';
        }
        return 'strong';
    }

    private function source_key_for_row($spec, $row, $offset) {
        $pk = $spec['pk'] ?? '';
        if ($pk !== '' && isset($row[$pk])) return (string)$row[$pk];
        return 'offset-' . (int)$offset;
    }

    private function source_detail_for_row($table, $row, $key) {
        global $wpdb;
        if ($table === $wpdb->posts) {
            $title = trim(wp_strip_all_tags((string)($row['post_title'] ?? '')));
            return sprintf('Post #%d%s [%s / %s]', (int)($row['ID'] ?? 0), $title ? ': ' . $title : '', (string)($row['post_type'] ?? ''), (string)($row['post_status'] ?? ''));
        }
        if ($table === $wpdb->postmeta) {
            return sprintf('Post meta #%d — post #%d — key %s', (int)($row['meta_id'] ?? 0), (int)($row['post_id'] ?? 0), (string)($row['meta_key'] ?? ''));
        }
        if ($table === $wpdb->options) {
            return 'Option: ' . (string)($row['option_name'] ?? $key);
        }
        return $table . ' row ' . $key;
    }

    private function extract_media_tokens($text) {
        $text = html_entity_decode((string)$text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $tokens = [];
        $path_basenames = [];
        $ext = '(?:jpe?g|png|gif|webp|svg|avif|heic|pdf|docx?|xlsx?|pptx?|csv|txt|zip|gpx|kml|kmz)';

        if (preg_match_all('~wp-content/uploads/([^"\'<>\s?#]+\.' . $ext . ')~i', $text, $m)) {
            foreach ($m[1] as $raw) {
                $v = $this->normalize_alias($raw);
                if ($v !== '') {
                    $tokens['path|' . $v] = ['kind' => 'path', 'value' => $v];
                    $path_basenames[basename($v)] = true;
                }
            }
        }
        if (preg_match_all('~(?:^|["\'\s(=:/])((?:20\d{2}/\d{2}/)[A-Za-z0-9._%+()\-/]+\.' . $ext . ')~im', $text, $m)) {
            foreach ($m[1] as $raw) {
                $v = $this->normalize_alias($raw);
                if ($v !== '') {
                    $tokens['path|' . $v] = ['kind' => 'path', 'value' => $v];
                    $path_basenames[basename($v)] = true;
                }
            }
        }
        if (preg_match_all('~([A-Za-z0-9][A-Za-z0-9._%+()\-]{1,190}\.' . $ext . ')~i', $text, $m)) {
            foreach ($m[1] as $raw) {
                $v = $this->normalize_alias(basename(rawurldecode($raw)));
                if ($v === '' || isset($path_basenames[$v])) continue;
                $tokens['basename|' . $v] = ['kind' => 'basename', 'value' => $v];
            }
        }

        return array_values($tokens);
    }

    private function extract_attachment_ids($text) {
        $ids = [];
        $patterns = [
            '/wp-image-(\d{1,10})/i',
            '/<!--\s*wp:image\s+\{[^}]*"id"\s*:\s*(\d{1,10})/i',
            '/(?:attachment|image|media|photo|thumbnail|file|gpx|gallery|route|download|document|pdf)[_-]?(?:id|ids)?["\']?\s*[:=]\s*["\']?(\d{1,10})/i',
        ];
        foreach ($patterns as $p) {
            if (preg_match_all($p, $text, $m)) {
                foreach ($m[1] as $id) $ids[(int)$id] = true;
            }
        }
        // Serialized/JSON plugin data may use keys such as "gpx", "photos" or
        // "gallery" without an explicit *_id suffix.
        $media_key = '(?:attachment|image|images|media|photo|photos|thumbnail|file|files|gpx|gallery|route_file|download|document|pdf)';
        $context_patterns = [
            '/["\']' . $media_key . '["\']\s*[:=]\s*["\']?(\d{1,10})/i',
            '/s:\d+:"' . $media_key . '";i:(\d{1,10})/i',
        ];
        foreach ($context_patterns as $p) {
            if (preg_match_all($p, $text, $m)) {
                foreach ($m[1] as $id) $ids[(int)$id] = true;
            }
        }

        if (preg_match_all('/\bids\s*=\s*["\']([\d,\s]+)["\']/i', $text, $m)) {
            foreach ($m[1] as $csv) {
                foreach (preg_split('/\s*,\s*/', trim($csv)) as $id) {
                    if (ctype_digit($id)) $ids[(int)$id] = true;
                }
            }
        }
        return array_keys(array_filter($ids, function($v, $k){ return $k > 0; }, ARRAY_FILTER_USE_BOTH));
    }

    private function add_token_refs($tokens, $strength, $source_type, $source_table, $source_key, $source_detail) {
        global $wpdb;
        if (!$tokens) return;

        foreach ($tokens as $token) {
            $value = $this->normalize_alias($token['value']);
            if ($value === '') continue;

            $matches = $this->find_alias_items($value, $token['kind']);
            // If a full path did not resolve, fall back to basename. This is conservative.
            if (!$matches && $token['kind'] === 'path') {
                $matches = $this->find_alias_items(basename($value), 'basename');
            }
            foreach ($matches as $item_id) {
                $this->insert_ref($item_id, $strength, $source_type, $source_table, $source_key, $source_detail, $value);
            }
        }
    }

    private function add_attachment_id_refs($ids, $strength, $source_type, $source_table, $source_key, $source_detail, $matched) {
        global $wpdb;
        $ids = array_values(array_unique(array_filter(array_map('intval', $ids))));
        if (!$ids) return;
        $placeholders = implode(',', array_fill(0, count($ids), '%d'));
        $sql = $wpdb->prepare("SELECT id, attachment_id FROM {$this->items_table} WHERE attachment_id IN ({$placeholders})", $ids);
        foreach ($wpdb->get_results($sql) as $row) {
            $this->insert_ref((int)$row->id, $strength, $source_type, $source_table, $source_key, $source_detail, $matched . ' #' . (int)$row->attachment_id);
        }
    }

    private function find_alias_items($value, $kind) {
        global $wpdb;
        $value = $this->normalize_alias($value);
        if ($value === '') return [];
        $hash = md5($value);
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT item_id, alias_text, alias_kind FROM {$this->aliases_table} WHERE alias_hash=%s",
            $hash
        ));
        $ids = [];
        foreach ($rows as $row) {
            if ($row->alias_text === $value && ($kind === 'basename' ? $row->alias_kind === 'basename' : true)) {
                $ids[(int)$row->item_id] = true;
            }
        }
        return array_keys($ids);
    }

    private function insert_ref($item_id, $strength, $source_type, $source_table, $source_key, $source_detail, $matched_alias) {
        global $wpdb;
        $strength = $strength === 'weak' ? 'weak' : 'strong';
        $hash = md5(implode('|', [$item_id, $strength, $source_type, $source_table, $source_key, $matched_alias]));
        $wpdb->query($wpdb->prepare(
            "INSERT IGNORE INTO {$this->refs_table}
            (item_id, strength, source_type, source_table, source_key, source_detail, matched_alias, ref_hash)
            VALUES (%d,%s,%s,%s,%s,%s,%s,%s)",
            $item_id, $strength, $source_type, $source_table, (string)$source_key, (string)$source_detail, (string)$matched_alias, $hash
        ));
    }

    private function add_alias($item_id, $value, $kind) {
        global $wpdb;
        $norm = $this->normalize_alias($value);
        if ($norm === '') return;
        $wpdb->query($wpdb->prepare(
            "INSERT IGNORE INTO {$this->aliases_table} (item_id, alias_hash, alias_text, alias_kind) VALUES (%d,%s,%s,%s)",
            $item_id, md5($norm), $norm, $kind === 'path' ? 'path' : 'basename'
        ));
    }

    private function normalize_alias($value) {
        $value = html_entity_decode((string)$value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $value = rawurldecode($value);
        $value = str_replace('\\', '/', $value);
        $value = preg_replace('/[?#].*$/', '', $value);
        $needle = 'wp-content/uploads/';
        $pos = stripos($value, $needle);
        if ($pos !== false) {
            $value = substr($value, $pos + strlen($needle));
        }
        $value = trim($value, " \t\n\r\0\x0B\"'()[]{}<>");
        $value = ltrim($value, '/');
        $value = preg_replace('~/+~', '/', $value);
        return strtolower($value);
    }

    private function is_auditable_upload_path($rel) {
        $rel = $this->safe_rel_path($rel);
        if ($rel === '') return false;
        if (basename($rel) === '.htaccess' || basename($rel) === 'index.php') return false;
        // Normal WordPress media uploads live in year-based folders. Also allow root-level media files.
        if (preg_match('~^20\d{2}/~', $rel)) return true;
        return strpos($rel, '/') === false;
    }

    private function safe_rel_path($rel) {
        $rel = wp_normalize_path((string)$rel);
        $rel = ltrim($rel, '/');
        if ($rel === '' || strpos($rel, '../') !== false || $rel === '..') return '';
        return $rel;
    }

    private function uploads_abs($rel) {
        $uploads = wp_get_upload_dir();
        $base = rtrim(wp_normalize_path($uploads['basedir']), '/');
        $rel = $this->safe_rel_path($rel);
        return $rel === '' ? '' : $base . '/' . $rel;
    }

    private function qi($identifier) {
        return '`' . str_replace('`', '``', $identifier) . '`';
    }

    private function set_nonautoload_option($name, $value) {
        if (get_option($name, null) === null) {
            add_option($name, $value, '', 'no');
        } else {
            update_option($name, $value, false);
        }
    }

    private function quarantine_root() {
        $token = get_option(self::QUARANTINE_TOKEN_OPTION);
        if (!$token) {
            $token = wp_generate_password(24, false, false);
            add_option(self::QUARANTINE_TOKEN_OPTION, $token, '', 'no');
        }
        $root = wp_normalize_path(WP_CONTENT_DIR . '/ubes-media-quarantine-' . preg_replace('/[^A-Za-z0-9_-]/', '', $token));
        if (!is_dir($root)) {
            wp_mkdir_p($root);
            @file_put_contents($root . '/index.php', "<?php\nhttp_response_code(404);\nexit;\n");
            @file_put_contents($root . '/.htaccess', "Require all denied\nDeny from all\n");
        }
        return $root;
    }

    public function handle_bulk() {
        if (!current_user_can('manage_options')) wp_die('Permission denied.');
        check_admin_referer('ubes_ma_bulk');
        $action = sanitize_key($_POST['bulk_action'] ?? '');
        $scope = sanitize_key($_POST['selection_scope'] ?? 'page');

        if ($scope === 'filtered') {
            $ids = $this->filtered_ids_from_post();
        } else {
            $ids = array_values(array_unique(array_filter(array_map('intval', (array)($_POST['item_ids'] ?? [])))));
        }

        if (!$action || !$ids) {
            $this->redirect_notice('Choose an action and at least one item.', 'error');
        }

        // Large filtered batches can involve hundreds of filesystem moves.
        // Give the admin action a little more room without changing site-wide PHP settings.
        if (function_exists('set_time_limit')) @set_time_limit(300);

        $ok = 0;
        $errors = [];
        foreach ($ids as $id) {
            $result = $this->bulk_item_action($id, $action);
            if (is_wp_error($result)) {
                $errors[] = '#' . $id . ': ' . $result->get_error_message();
            } else {
                $ok++;
            }
        }

        $msg = $ok . ' item(s) processed.';
        if ($errors) $msg .= ' ' . implode(' ', array_slice($errors, 0, 5));
        $this->redirect_notice($msg, $errors ? 'warning' : 'success');
    }

    private function filtered_ids_from_post() {
        global $wpdb;
        $status = sanitize_key($_POST['filter_status'] ?? '');
        $year = absint($_POST['filter_year'] ?? 0);
        $search = sanitize_text_field(wp_unslash($_POST['filter_search'] ?? ''));

        [$where_sql, $params] = $this->build_filter_where($status, $year, $search);
        $sql = "SELECT id FROM {$this->items_table} WHERE {$where_sql} ORDER BY id ASC";
        return array_map('intval', $params ? $wpdb->get_col($wpdb->prepare($sql, $params)) : $wpdb->get_col($sql));
    }

    private function build_filter_where($status, $year, $search) {
        global $wpdb;
        $where = ['1=1'];
        $params = [];

        if ($status) {
            if ($status === 'safe_candidate') {
                $where[] = "status='candidate' AND is_orphan=1 AND strong_refs=0 AND weak_refs=0 AND parent_id=0";
            } elseif ($status === 'candidate_orphan') {
                $where[] = "status='candidate' AND is_orphan=1";
            } elseif ($status === 'orphan') {
                $where[] = 'is_orphan=1';
            } elseif (in_array($status, ['used','candidate','keep','quarantined','missing'], true)) {
                $where[] = 'status=%s';
                $params[] = $status;
            }
        }
        if ($year >= 2000 && $year <= 2100) {
            $where[] = 'YEAR(uploaded_at)=%d';
            $params[] = $year;
        }
        if ($search !== '') {
            $where[] = '(file_name LIKE %s OR rel_path LIKE %s)';
            $like = '%' . $wpdb->esc_like($search) . '%';
            $params[] = $like;
            $params[] = $like;
        }
        return [implode(' AND ', $where), $params];
    }

    private function bulk_item_action($id, $action) {
        global $wpdb;
        $item = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$this->items_table} WHERE id=%d", $id));
        if (!$item) return new WP_Error('missing_item', 'Item not found.');

        switch ($action) {
            case 'mark_keep':
                if ($item->status === 'quarantined') return new WP_Error('quarantined', 'Restore quarantined items before marking Keep.');
                $wpdb->update($this->items_table, ['manual_keep' => 1, 'status' => 'keep'], ['id' => $id]);
                return true;
            case 'unmark_keep':
                if ($item->status === 'quarantined') return new WP_Error('quarantined', 'Restore quarantined items first.');
                $status = $this->calculated_status($item, false);
                $wpdb->update($this->items_table, ['manual_keep' => 0, 'status' => $status], ['id' => $id]);
                return true;
            case 'quarantine':
                return $this->quarantine_item($item);
            case 'restore':
                return $this->restore_item($item);
            case 'delete_permanently':
                return $this->delete_quarantined_item($item);
            default:
                return new WP_Error('bad_action', 'Unknown bulk action.');
        }
    }

    private function calculated_status($item, $manual_keep = null) {
        if ($manual_keep === null) $manual_keep = (bool)$item->manual_keep;
        if ($manual_keep) return 'keep';
        if ($item->attachment_id && !is_file($this->uploads_abs($item->rel_path))) return 'missing';
        if ((int)$item->strong_refs > 0) return 'used';
        return 'candidate';
    }

    private function quarantine_item($item) {
        global $wpdb;
        if ($item->status === 'quarantined') return true;
        if ((int)$item->strong_refs > 0) {
            return new WP_Error('used', 'Strong references were found; this item is protected from quarantine.');
        }
        if ((int)$item->manual_keep === 1) {
            return new WP_Error('keep', 'This item is marked Keep. Unmark it first.');
        }

        $files = json_decode((string)$item->family_files, true);
        if (!is_array($files) || !$files) $files = [$item->rel_path];
        $files = array_values(array_unique(array_filter(array_map([$this, 'safe_rel_path'], $files))));
        $qroot = $this->quarantine_root();
        $moves = [];

        foreach ($files as $rel) {
            $src = $this->uploads_abs($rel);
            if (!is_file($src)) continue;
            $dst = $qroot . '/' . $rel;
            if (is_file($dst)) {
                return new WP_Error('q_conflict', 'A quarantine copy already exists for ' . $rel . '.');
            }
            $moves[] = [$src, $dst, $rel];
        }
        if (!$moves) {
            return new WP_Error('no_files', 'No existing files were found to quarantine.');
        }

        $done = [];
        foreach ($moves as [$src, $dst, $rel]) {
            wp_mkdir_p(dirname($dst));
            if (!$this->move_file($src, $dst)) {
                foreach (array_reverse($done) as [$s, $d]) {
                    $this->move_file($d, $s);
                }
                return new WP_Error('move_failed', 'Could not quarantine ' . $rel . '. Earlier moves were rolled back.');
            }
            $done[] = [$src, $dst, $rel];
        }

        $manifest = ['moved_at' => current_time('mysql'), 'files' => array_map(function($m){ return $m[2]; }, $done)];
        $wpdb->update($this->items_table, [
            'status' => 'quarantined',
            'quarantine_data' => wp_json_encode($manifest),
        ], ['id' => (int)$item->id]);
        return true;
    }

    private function restore_item($item) {
        global $wpdb;
        if ($item->status !== 'quarantined') return new WP_Error('not_quarantined', 'Item is not quarantined.');
        $manifest = json_decode((string)$item->quarantine_data, true);
        $files = is_array($manifest) && !empty($manifest['files']) ? $manifest['files'] : [];
        if (!$files) return new WP_Error('manifest', 'Quarantine manifest is missing.');
        $qroot = $this->quarantine_root();

        foreach ($files as $rel) {
            $rel = $this->safe_rel_path($rel);
            $dst = $this->uploads_abs($rel);
            if (is_file($dst)) return new WP_Error('restore_conflict', 'Cannot restore because a file now exists at ' . $rel . '.');
            if (!is_file($qroot . '/' . $rel)) return new WP_Error('restore_missing', 'Quarantine file is missing: ' . $rel . '.');
        }

        $done = [];
        foreach ($files as $rel) {
            $rel = $this->safe_rel_path($rel);
            $src = $qroot . '/' . $rel;
            $dst = $this->uploads_abs($rel);
            wp_mkdir_p(dirname($dst));
            if (!$this->move_file($src, $dst)) {
                foreach (array_reverse($done) as [$s, $d]) {
                    $this->move_file($d, $s);
                }
                return new WP_Error('restore_failed', 'Could not restore ' . $rel . '. Earlier restores were rolled back.');
            }
            $done[] = [$src, $dst, $rel];
        }

        $fresh = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$this->items_table} WHERE id=%d", (int)$item->id));
        $status = $this->calculated_status($fresh ?: $item);
        $wpdb->update($this->items_table, ['status' => $status, 'quarantine_data' => null], ['id' => (int)$item->id]);
        return true;
    }

    private function delete_quarantined_item($item) {
        global $wpdb;
        if ($item->status !== 'quarantined') {
            return new WP_Error('not_quarantined', 'Permanent deletion is only allowed from quarantine.');
        }
        $manifest = json_decode((string)$item->quarantine_data, true);
        $files = is_array($manifest) && !empty($manifest['files']) ? $manifest['files'] : [];
        $qroot = $this->quarantine_root();

        foreach ($files as $rel) {
            $rel = $this->safe_rel_path($rel);
            if (is_file($this->uploads_abs($rel))) {
                return new WP_Error('delete_conflict', 'A file now exists again at ' . $rel . '; deletion stopped to protect it.');
            }
        }

        foreach ($files as $rel) {
            $rel = $this->safe_rel_path($rel);
            $qfile = $qroot . '/' . $rel;
            if (is_file($qfile) && !@unlink($qfile)) {
                return new WP_Error('unlink_failed', 'Could not permanently delete quarantine file ' . $rel . '.');
            }
        }

        if (!empty($item->attachment_id)) {
            wp_delete_attachment((int)$item->attachment_id, true);
        }
        $wpdb->delete($this->refs_table, ['item_id' => (int)$item->id]);
        $wpdb->delete($this->aliases_table, ['item_id' => (int)$item->id]);
        $wpdb->delete($this->items_table, ['id' => (int)$item->id]);
        return true;
    }

    private function move_file($src, $dst) {
        if (@rename($src, $dst)) return true;
        if (@copy($src, $dst)) {
            if (@unlink($src)) return true;
            @unlink($dst);
        }
        return false;
    }

    private function redirect_notice($message, $type='success') {
        $url = add_query_arg([
            'page' => self::MENU_SLUG,
            'ubes_ma_notice' => $message,
            'ubes_ma_type' => sanitize_key($type),
        ], admin_url('upload.php'));
        wp_safe_redirect($url);
        exit;
    }

    public function handle_export() {
        if (!current_user_can('manage_options')) wp_die('Permission denied.');
        check_admin_referer('ubes_ma_export');
        global $wpdb;
        $rows = $wpdb->get_results("SELECT attachment_id, rel_path, file_name, mime_type, uploaded_at, family_bytes, width, height, is_orphan, parent_id, strong_refs, weak_refs, status, manual_keep FROM {$this->items_table} ORDER BY uploaded_at ASC, rel_path ASC", ARRAY_A);
        nocache_headers();
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="ubes-media-audit-' . gmdate('Y-m-d-His') . '.csv"');
        $out = fopen('php://output', 'w');
        if ($rows) {
            fputcsv($out, array_keys($rows[0]));
            foreach ($rows as $row) fputcsv($out, $row);
        }
        fclose($out);
        exit;
    }

    public function render_admin_page() {
        if (!current_user_can('manage_options')) return;
        $this->ensure_tables();
        global $wpdb;

        $notice = isset($_GET['ubes_ma_notice']) ? sanitize_text_field(wp_unslash($_GET['ubes_ma_notice'])) : '';
        $notice_type = isset($_GET['ubes_ma_type']) ? sanitize_key($_GET['ubes_ma_type']) : 'success';

        $total = (int)$wpdb->get_var("SELECT COUNT(*) FROM {$this->items_table}");
        $used = (int)$wpdb->get_var("SELECT COUNT(*) FROM {$this->items_table} WHERE status='used'");
        $candidates = (int)$wpdb->get_var("SELECT COUNT(*) FROM {$this->items_table} WHERE status='candidate'");
        $orphan = (int)$wpdb->get_var("SELECT COUNT(*) FROM {$this->items_table} WHERE is_orphan=1 AND status<>'quarantined'");
        $quarantined = (int)$wpdb->get_var("SELECT COUNT(*) FROM {$this->items_table} WHERE status='quarantined'");
        $potential = (int)$wpdb->get_var("SELECT COALESCE(SUM(family_bytes),0) FROM {$this->items_table} WHERE status='candidate'");
        $total_bytes = (int)$wpdb->get_var("SELECT COALESCE(SUM(family_bytes),0) FROM {$this->items_table} WHERE is_orphan=0") + (int)$wpdb->get_var("SELECT COALESCE(SUM(family_bytes),0) FROM {$this->items_table} WHERE is_orphan=1");

        $state = get_option(self::STATE_OPTION, []);
        $scan_complete = !empty($state['stage']) && $state['stage'] === 'complete';

        echo '<div class="wrap ubes-ma-wrap"><h1>UBES Media Audit</h1>';
        if ($notice) {
            $class = $notice_type === 'success' ? 'notice-success' : ($notice_type === 'error' ? 'notice-error' : 'notice-warning');
            echo '<div class="notice ' . esc_attr($class) . ' is-dismissible"><p>' . esc_html($notice) . '</p></div>';
        }

        echo '<div class="ubes-ma-hero"><div><h2>Conservative media cleanup</h2><div class="ubes-ma-muted">Scans the Media Library, normal uploads folders, WordPress database, active theme and active plugins. Files with strong references are protected from quarantine.</div></div><div><button type="button" class="button button-primary" id="ubes-ma-start-scan">' . ($total ? 'Run full scan again' : 'Start full scan') . '</button></div><div class="ubes-ma-progress"><div class="ubes-ma-progress-track"><div class="ubes-ma-progress-bar"></div></div><div class="ubes-ma-progress-text">Ready.</div></div></div>';

        if ($quarantined > 0) {
            echo '<div class="ubes-ma-note"><strong>' . number_format($quarantined) . ' item(s) are in quarantine.</strong> Restore or permanently delete them before starting another full scan.</div>';
        } elseif ($scan_complete && $candidates > 0) {
            echo '<div class="ubes-ma-good"><strong>No automatic deletion occurs.</strong> Review Candidate items, quarantine a batch, inspect the live site, then either Restore or Permanently delete from quarantine.</div>';
        }

        echo '<div class="ubes-ma-stats">';
        $this->stat_box('Items', number_format($total));
        $this->stat_box('Used', number_format($used));
        $this->stat_box('Candidates', number_format($candidates));
        $this->stat_box('Filesystem orphans', number_format($orphan));
        $this->stat_box('Potential recovery', size_format($potential));
        $this->stat_box('Audited footprint', size_format($total_bytes));
        echo '</div>';

        if (isset($_GET['detail'])) {
            $this->render_detail((int)$_GET['detail']);
        }

        $this->render_table();
        echo '</div>';
    }

    private function stat_box($label, $value) {
        echo '<div class="ubes-ma-stat"><strong>' . esc_html($value) . '</strong><span>' . esc_html($label) . '</span></div>';
    }

    private function render_detail($id) {
        global $wpdb;
        $item = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$this->items_table} WHERE id=%d", $id));
        if (!$item) return;
        $refs = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$this->refs_table} WHERE item_id=%d ORDER BY strength ASC, source_type ASC, source_table ASC, source_key ASC", $id));
        $family = json_decode((string)$item->family_files, true);
        if (!is_array($family)) $family = [];

        echo '<div class="ubes-ma-detail"><div class="ubes-ma-toolbar"><h2 style="margin:0">' . esc_html($item->file_name) . '</h2><a class="button" href="' . esc_url(admin_url('upload.php?page=' . self::MENU_SLUG)) . '">Close details</a></div>';
        echo '<div class="ubes-ma-detail-grid">';
        echo '<div><strong>Status</strong><br>' . $this->status_badge($item) . '</div>';
        echo '<div><strong>Attachment ID</strong><br>' . ($item->attachment_id ? '#' . (int)$item->attachment_id : 'Filesystem only') . '</div>';
        echo '<div><strong>Uploaded</strong><br>' . esc_html($item->uploaded_at ?: 'Unknown') . '</div>';
        echo '<div><strong>Total family size</strong><br>' . esc_html(size_format((int)$item->family_bytes)) . '</div>';
        echo '<div><strong>Dimensions</strong><br>' . ((int)$item->width && (int)$item->height ? (int)$item->width . ' × ' . (int)$item->height : '—') . '</div>';
        echo '<div><strong>References</strong><br>' . (int)$item->strong_refs . ' strong / ' . (int)$item->weak_refs . ' weak</div>';
        echo '</div>';
        echo '<p><strong>Relative path:</strong><br><code>' . esc_html($item->rel_path) . '</code></p>';
        echo '<h3>File family</h3><div class="ubes-ma-family">' . implode('<br>', array_map('esc_html', $family)) . '</div>';
        echo '<h3>References found</h3>';
        if (!$refs) {
            echo '<p>No database or active-code references were found.</p>';
        } else {
            echo '<table class="widefat striped ubes-ma-ref-table"><thead><tr><th>Strength</th><th>Source</th><th>Where</th><th>Matched</th></tr></thead><tbody>';
            foreach ($refs as $r) {
                echo '<tr><td>' . esc_html(ucfirst($r->strength)) . '</td><td>' . esc_html($r->source_type) . '</td><td>' . esc_html($r->source_detail ?: ($r->source_table . ' ' . $r->source_key)) . '</td><td><code>' . esc_html($r->matched_alias) . '</code></td></tr>';
            }
            echo '</tbody></table>';
        }
        echo '</div>';
    }

    private function render_table() {
        global $wpdb;
        $status = isset($_GET['status']) ? sanitize_key($_GET['status']) : '';
        $year = isset($_GET['year']) ? absint($_GET['year']) : 0;
        $search = isset($_GET['s']) ? sanitize_text_field(wp_unslash($_GET['s'])) : '';
        $orderby = isset($_GET['orderby']) ? sanitize_key($_GET['orderby']) : 'uploaded_at';
        $order = isset($_GET['order']) && strtolower($_GET['order']) === 'asc' ? 'ASC' : 'DESC';
        $page_num = max(1, isset($_GET['paged']) ? absint($_GET['paged']) : 1);
        $per_page = 50;
        $offset = ($page_num - 1) * $per_page;

        $allowed_order = [
            'uploaded_at' => 'uploaded_at',
            'file_name' => 'file_name',
            'family_bytes' => 'family_bytes',
            'strong_refs' => 'strong_refs',
            'status' => 'status',
        ];
        $order_col = $allowed_order[$orderby] ?? 'uploaded_at';

        [$where_sql, $params] = $this->build_filter_where($status, $year, $search);
        $count_sql = "SELECT COUNT(*) FROM {$this->items_table} WHERE {$where_sql}";
        $total = $params ? (int)$wpdb->get_var($wpdb->prepare($count_sql, $params)) : (int)$wpdb->get_var($count_sql);

        $data_sql = "SELECT * FROM {$this->items_table} WHERE {$where_sql} ORDER BY {$order_col} {$order}, id DESC LIMIT %d OFFSET %d";
        $data_params = array_merge($params, [$per_page, $offset]);
        $rows = $wpdb->get_results($wpdb->prepare($data_sql, $data_params));

        $years = $wpdb->get_col("SELECT DISTINCT YEAR(uploaded_at) y FROM {$this->items_table} WHERE uploaded_at IS NOT NULL ORDER BY y DESC");

        echo '<div class="ubes-ma-toolbar"><form method="get" class="ubes-ma-filters"><input type="hidden" name="page" value="' . esc_attr(self::MENU_SLUG) . '"><select name="status"><option value="">All statuses</option>';
        $opts = ['safe_candidate'=>'Safe candidates (orphan + zero refs)','candidate_orphan'=>'Candidate filesystem orphans','candidate'=>'Candidates','orphan'=>'Filesystem orphans (all)','used'=>'Used','keep'=>'Keep','quarantined'=>'Quarantined','missing'=>'Missing'];
        foreach ($opts as $k=>$v) echo '<option value="' . esc_attr($k) . '" ' . selected($status,$k,false) . '>' . esc_html($v) . '</option>';
        echo '</select><select name="year"><option value="0">All years</option>';
        foreach ($years as $y) if ($y) echo '<option value="' . (int)$y . '" ' . selected($year,(int)$y,false) . '>' . (int)$y . '</option>';
        echo '</select><input type="search" name="s" value="' . esc_attr($search) . '" placeholder="Filename or path"><button class="button">Filter</button></form>';
        $export_url = wp_nonce_url(admin_url('admin-post.php?action=ubes_ma_export'), 'ubes_ma_export');
        echo '<a class="button" href="' . esc_url($export_url) . '">Export audit CSV</a></div>';

        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" id="ubes-ma-bulk-form" data-filtered-total="' . (int)$total . '"><input type="hidden" name="action" value="ubes_ma_bulk">';
        wp_nonce_field('ubes_ma_bulk');
        echo '<input type="hidden" name="selection_scope" id="ubes-ma-selection-scope" value="page">';
        echo '<input type="hidden" name="filter_status" value="' . esc_attr($status) . '">';
        echo '<input type="hidden" name="filter_year" value="' . (int)$year . '">';
        echo '<input type="hidden" name="filter_search" value="' . esc_attr($search) . '">';
        echo '<div class="tablenav top"><div class="alignleft actions"><select name="bulk_action" id="ubes-ma-bulk-action"><option value="">Bulk actions</option><option value="mark_keep">Mark Keep</option><option value="unmark_keep">Unmark Keep</option><option value="quarantine">Quarantine selected</option><option value="restore">Restore selected</option><option value="delete_permanently">Delete permanently (quarantine only)</option></select><button class="button action">Apply</button></div>';
        $this->pagination($total, $per_page, $page_num);
        echo '</div>';
        echo '<div class="ubes-ma-selection"><span id="ubes-ma-selection-message"></span> <a href="#" id="ubes-ma-select-all-filtered"></a> <a href="#" id="ubes-ma-clear-selection" style="margin-left:10px">Clear selection</a></div>';

        echo '<table class="wp-list-table widefat fixed striped table-view-list ubes-ma-table"><thead><tr><td class="manage-column column-cb check-column"><input type="checkbox" id="ubes-ma-check-all"></td><th style="width:70px">Preview</th>';
        echo $this->sortable_th('File','file_name',$orderby,$order);
        echo $this->sortable_th('Uploaded','uploaded_at',$orderby,$order,'width:125px');
        echo $this->sortable_th('Space','family_bytes',$orderby,$order,'width:90px');
        echo '<th style="width:95px">Dimensions</th>';
        echo $this->sortable_th('References','strong_refs',$orderby,$order,'width:105px');
        echo $this->sortable_th('Status','status',$orderby,$order,'width:115px');
        echo '</tr></thead><tbody>';

        if (!$rows) {
            echo '<tr><td colspan="9">No media items match this view.</td></tr>';
        } else {
            foreach ($rows as $item) {
                $preview = $this->preview_html($item);
                $detail_url = add_query_arg(array_merge($_GET, ['page'=>self::MENU_SLUG,'detail'=>(int)$item->id]), admin_url('upload.php'));
                echo '<tr><th scope="row" class="check-column"><input class="ubes-ma-row-check" type="checkbox" name="item_ids[]" value="' . (int)$item->id . '"></th><td>' . $preview . '</td><td><div class="ubes-ma-file">' . esc_html($item->file_name) . '</div><div class="ubes-ma-path">' . esc_html($item->rel_path) . '</div>';
                if ((int)$item->is_orphan) echo '<span class="ubes-ma-badge ubes-ma-orphan">Filesystem only</span> ';
                if ((int)$item->parent_id) echo '<span class="ubes-ma-muted">Parent #' . (int)$item->parent_id . '</span>';
                echo '<div><a href="' . esc_url($detail_url) . '">View audit details</a></div></td>';
                echo '<td>' . esc_html($item->uploaded_at ? mysql2date('Y-m-d', $item->uploaded_at) : '—') . '</td>';
                echo '<td>' . esc_html(size_format((int)$item->family_bytes)) . '</td>';
                echo '<td>' . (((int)$item->width && (int)$item->height) ? (int)$item->width . '×' . (int)$item->height : '—') . '</td>';
                echo '<td><strong>' . (int)$item->strong_refs . '</strong> strong';
                if ((int)$item->weak_refs) echo '<br><span class="ubes-ma-weak">' . (int)$item->weak_refs . ' weak</span>';
                echo '</td><td>' . $this->status_badge($item) . '</td></tr>';
            }
        }
        echo '</tbody></table>';
        echo '<div class="tablenav bottom">';
        $this->pagination($total, $per_page, $page_num);
        echo '</div></form>';
        echo '<p class="description"><strong>Strong reference</strong> = current content/settings/code, a rendered public page, or another authoritative database location. <strong>Weak reference</strong> = cache, logs, analytics, revisions/trash or similar historical/derived data. Candidate means no strong reference was found; it is not a guarantee that the file is unused. Tick the header checkbox to select the current page, then use <strong>Select all items matching these filters</strong> to apply a bulk action across every results page.</p>';
    }

    private function sortable_th($label,$key,$orderby,$order,$style='') {
        $new_order = ($orderby === $key && $order === 'ASC') ? 'desc' : 'asc';
        $url = add_query_arg(array_merge($_GET, ['page'=>self::MENU_SLUG,'orderby'=>$key,'order'=>$new_order,'paged'=>1]), admin_url('upload.php'));
        return '<th ' . ($style ? 'style="' . esc_attr($style) . '"' : '') . '><a href="' . esc_url($url) . '"><span>' . esc_html($label) . '</span></a></th>';
    }

    private function pagination($total,$per_page,$page_num) {
        $pages = max(1, (int)ceil($total / $per_page));
        if ($pages <= 1) return;
        $base_args = $_GET;
        unset($base_args['paged'], $base_args['detail']);
        $base_args['page'] = self::MENU_SLUG;
        echo '<div class="tablenav-pages"><span class="displaying-num">' . number_format($total) . ' items</span><span class="pagination-links">';
        if ($page_num > 1) {
            echo '<a class="button" href="' . esc_url(add_query_arg(array_merge($base_args,['paged'=>$page_num-1]),admin_url('upload.php'))) . '">‹</a> ';
        }
        echo '<span class="paging-input">' . (int)$page_num . ' of <span class="total-pages">' . (int)$pages . '</span></span>';
        if ($page_num < $pages) {
            echo ' <a class="button" href="' . esc_url(add_query_arg(array_merge($base_args,['paged'=>$page_num+1]),admin_url('upload.php'))) . '">›</a>';
        }
        echo '</span></div>';
    }

    private function preview_html($item) {
        if ($item->status === 'quarantined') return '<div class="ubes-ma-thumb"></div>';
        if (strpos((string)$item->mime_type, 'image/') !== 0) return '<div class="ubes-ma-thumb"></div>';
        $uploads = wp_get_upload_dir();
        $url = trailingslashit($uploads['baseurl']) . ltrim($item->rel_path, '/');
        return '<img class="ubes-ma-thumb" loading="lazy" src="' . esc_url($url) . '" alt="">';
    }

    private function status_badge($item) {
        $status = (string)$item->status;
        $labels = [
            'used' => ['Used','ubes-ma-used'],
            'candidate' => ['Candidate','ubes-ma-candidate'],
            'keep' => ['Keep','ubes-ma-keep'],
            'quarantined' => ['Quarantined','ubes-ma-quarantined'],
            'missing' => ['Missing','ubes-ma-missing'],
            'unknown' => ['Unscanned','ubes-ma-orphan'],
        ];
        $x = $labels[$status] ?? [ucfirst($status),'ubes-ma-orphan'];
        return '<span class="ubes-ma-badge ' . esc_attr($x[1]) . '">' . esc_html($x[0]) . '</span>';
    }
}

register_activation_hook(__FILE__, ['UBES_Media_Audit', 'activate']);
UBES_Media_Audit::instance();
