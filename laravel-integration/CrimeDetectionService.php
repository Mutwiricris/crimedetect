<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Exception;

/**
 * AI Crime Detection Engine — Laravel Service
 *
 * Provides methods to call the FastAPI inference engine:
 *   - analyzeUrl()        → detect phishing / malicious URLs
 *   - analyzeNetwork()    → detect network intrusions/attacks
 *   - analyzeCyberbullying() → analyse user‑pair interaction stats
 *   - analyzeBatch()      → send up to 100 items in one request
 *
 * Configuration (config/services.php):
 *   'crime_detection' => [
 *       'url'     => env('CRIME_DETECT_URL', 'http://localhost:8000'),
 *       'api_key' => env('CRIME_DETECT_KEY'),
 *       'timeout' => 10,
 *   ]
 */
class CrimeDetectionService
{
    private string $baseUrl;
    private string $apiKey;
    private int    $timeout;

    public function __construct()
    {
        $config        = config('services.crime_detection');
        $this->baseUrl = rtrim($config['url'] ?? 'http://localhost:8000', '/');
        $this->apiKey  = $config['api_key'] ?? '';
        $this->timeout = (int) ($config['timeout'] ?? 10);
    }

    // ── Public API ─────────────────────────────────────────────────────────────

    /**
     * Analyse a URL for phishing / malicious content.
     *
     * @param  string $url  Full URL to analyse (e.g. "https://example.com/login?ref=1")
     * @return array{is_threat: bool, confidence_score: float, threat_category: string, model_used: string, timestamp: string}
     */
    public function analyzeUrl(string $url): array
    {
        return $this->analyze('url', $url);
    }

    /**
     * Analyse a network flow log for intrusions / attacks.
     *
     * @param  array $networkLog  Keys must match the UNSW-NB15 schema:
     *   dur, spkts, dpkts, sbytes, dbytes, rate, sttl, dttl, sload, dload,
     *   sloss, dloss, sinpkt, dinpkt, sjit, djit, swin, dwin,
     *   ct_srv_src, ct_state_ttl, ct_dst_ltm, ct_src_ltm, ct_srv_dst
     */
    public function analyzeNetwork(array $networkLog): array
    {
        return $this->analyze('network', $networkLog);
    }

    /**
     * Analyse a cyberbullying interaction using numeric user-pair statistics.
     *
     * @param  float $totalMessages   Total messages exchanged
     * @param  float $aggressiveCount Number of aggressive messages
     * @param  float $intentToHarm    Intent-to-harm score (0.0–1.0)
     * @param  float $peerness        Peerness score (0.0–1.0)
     */
    public function analyzeCyberbullying(
        float $totalMessages,
        float $aggressiveCount,
        float $intentToHarm,
        float $peerness
    ): array {
        return $this->analyze('cyberbullying', [
            'total_messages'   => $totalMessages,
            'aggressive_count' => $aggressiveCount,
            'intent_to_harm'   => $intentToHarm,
            'peerness'         => $peerness,
        ]);
    }

    /**
     * Analyse a free-text message for cyberbullying content.
     *
     * @param  string $text  Raw message text
     */
    public function analyzeText(string $text): array
    {
        return $this->analyze('cyberbullying', $text);
    }

    /**
     * Send up to 100 items in a single batch request.
     *
     * @param  array  $items  Each item must be ['type' => '...', 'data' => ...]
     * @return array  Array of prediction results in the same order as $items
     */
    public function analyzeBatch(array $items): array
    {
        if (count($items) > 100) {
            throw new \InvalidArgumentException('Batch size cannot exceed 100 items.');
        }

        $response = $this->client()->post("{$this->baseUrl}/batch", $items);

        if ($response->failed()) {
            Log::error('CrimeDetection batch failed', [
                'status' => $response->status(),
                'body'   => $response->body(),
            ]);
            throw new Exception("Crime detection batch request failed: HTTP {$response->status()}");
        }

        return $response->json();
    }

    /**
     * Check that the API server is healthy and all models are loaded.
     */
    public function health(): array
    {
        $response = Http::timeout($this->timeout)
            ->get("{$this->baseUrl}/health");

        if ($response->failed()) {
            throw new Exception("Crime detection health check failed: HTTP {$response->status()}");
        }

        return $response->json();
    }

    // ── Internal ───────────────────────────────────────────────────────────────

    private function client()
    {
        return Http::timeout($this->timeout)
            ->withHeaders([
                'X-API-Key'    => $this->apiKey,
                'Accept'       => 'application/json',
                'Content-Type' => 'application/json',
            ]);
    }

    private function analyze(string $type, mixed $data): array
    {
        $response = $this->client()->post("{$this->baseUrl}/analyze", [
            'type' => $type,
            'data' => $data,
        ]);

        if ($response->failed()) {
            Log::error('CrimeDetection request failed', [
                'type'   => $type,
                'status' => $response->status(),
                'body'   => $response->body(),
            ]);
            throw new Exception("Crime detection request failed: HTTP {$response->status()}");
        }

        return $response->json();
    }
}
