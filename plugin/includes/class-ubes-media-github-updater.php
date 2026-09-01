<?php
/**
 * GitHub Releases updater for UBES Media Audit.
 *
 * The Media Cleaner repository is public, so release metadata and the
 * installable ZIP can be fetched without storing credentials in WordPress.
 */

if (!defined('ABSPATH')) {
    exit;
}

final class UBES_Media_GitHub_Updater {
    private $plugin_basename;
    private $version;
    private $repo;
    private $asset_name;
    private $update_uri;
    private $slug;
    private $release_loaded = false;
    private $release = false;

    public function __construct($plugin_file, $version, $repo, $asset_name) {
        $this->plugin_basename = plugin_basename($plugin_file);
        $this->version = (string)$version;
        $this->repo = trim((string)$repo, '/');
        $this->asset_name = (string)$asset_name;
        $this->update_uri = 'https://github.com/' . $this->repo;
        $this->slug = dirname($this->plugin_basename);
        if ($this->slug === '.' || $this->slug === DIRECTORY_SEPARATOR) {
            $this->slug = basename($this->plugin_basename, '.php');
        }

        add_filter('update_plugins_github.com', [$this, 'filter_update'], 10, 4);
        add_filter('plugins_api', [$this, 'filter_plugin_information'], 20, 3);
    }

    private function cache_key() {
        return 'ubes_media_gh_rel_' . substr(md5($this->repo), 0, 18);
    }

    private function release() {
        if ($this->release_loaded) {
            return $this->release;
        }
        $this->release_loaded = true;

        $cached = get_site_transient($this->cache_key());
        if (is_array($cached) && !empty($cached['tag_name'])) {
            return $this->release = $cached;
        }

        $response = wp_remote_get(
            'https://api.github.com/repos/' . $this->repo . '/releases/latest',
            [
                'timeout' => 8,
                'redirection' => 3,
                'headers' => [
                    'Accept' => 'application/vnd.github+json',
                    'X-GitHub-Api-Version' => '2022-11-28',
                    'User-Agent' => 'UBES-Media-Audit-Updater/' . $this->version,
                ],
            ]
        );

        if (is_wp_error($response) || (int)wp_remote_retrieve_response_code($response) !== 200) {
            return false;
        }

        $data = json_decode(wp_remote_retrieve_body($response), true);
        if (!is_array($data) || empty($data['tag_name']) || empty($data['html_url'])) {
            return false;
        }

        set_site_transient($this->cache_key(), $data, 15 * MINUTE_IN_SECONDS);
        return $this->release = $data;
    }

    private function package_url($release) {
        foreach ((array)($release['assets'] ?? []) as $asset) {
            if (!is_array($asset) || ($asset['name'] ?? '') !== $this->asset_name) {
                continue;
            }
            if (!empty($asset['browser_download_url'])) {
                return esc_url_raw((string)$asset['browser_download_url']);
            }
        }
        return '';
    }

    private function update_data($release) {
        $version = preg_replace('/^v/i', '', trim((string)($release['tag_name'] ?? '')));
        if ($version === '') {
            return false;
        }

        return [
            'id' => $this->update_uri,
            'slug' => $this->slug,
            'version' => $version,
            'url' => esc_url_raw((string)$release['html_url']),
            'package' => $this->package_url($release),
            'autoupdate' => false,
        ];
    }

    public function filter_update($update, $plugin_data, $plugin_file, $locales) {
        if ((string)$plugin_file !== $this->plugin_basename) {
            return $update;
        }

        $release = $this->release();
        if (!$release) {
            return false;
        }

        return $this->update_data($release);
    }

    public function filter_plugin_information($result, $action, $args) {
        if ($action !== 'plugin_information' || !is_object($args)) {
            return $result;
        }
        if (empty($args->slug) || (string)$args->slug !== $this->slug) {
            return $result;
        }

        $release = $this->release();
        $data = $release ? $this->update_data($release) : false;
        if (!$data) {
            return $result;
        }

        $body = isset($release['body']) ? (string)$release['body'] : '';
        return (object)[
            'name' => 'UBES Media Audit',
            'slug' => $this->slug,
            'version' => $data['version'],
            'author' => 'UBES',
            'homepage' => $this->update_uri,
            'download_link' => $data['package'],
            'sections' => [
                'description' => 'Conservative media inventory, usage audit, quarantine/restore and bulk cleanup for the UBES WordPress site.',
                'changelog' => $body !== '' ? wpautop(esc_html($body)) : 'See the GitHub release notes for this version.',
            ],
        ];
    }
}
