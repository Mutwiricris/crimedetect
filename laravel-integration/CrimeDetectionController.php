<?php

namespace App\Http\Controllers;

use App\Services\CrimeDetectionService;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

/**
 * Example controller showing how to use CrimeDetectionService
 * in a real Laravel request lifecycle.
 *
 * Add to routes/api.php:
 *   Route::post('/scan/url',            [CrimeDetectionController::class, 'scanUrl']);
 *   Route::post('/scan/network',        [CrimeDetectionController::class, 'scanNetwork']);
 *   Route::post('/scan/cyberbullying',  [CrimeDetectionController::class, 'scanCyberbullying']);
 *   Route::post('/scan/batch',          [CrimeDetectionController::class, 'scanBatch']);
 *   Route::get ('/scan/health',         [CrimeDetectionController::class, 'health']);
 */
class CrimeDetectionController extends Controller
{
    public function __construct(private CrimeDetectionService $detector) {}

    // ── URL Scan ───────────────────────────────────────────────────────────────

    public function scanUrl(Request $request): JsonResponse
    {
        $request->validate(['url' => 'required|url']);

        try {
            $result = $this->detector->analyzeUrl($request->input('url'));
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 502);
        }

        // Optional: store result in DB, fire an event, etc.
        // ThreatLog::create([...]);

        return response()->json($result);
    }

    // ── Network Scan ───────────────────────────────────────────────────────────

    public function scanNetwork(Request $request): JsonResponse
    {
        $request->validate([
            'dur'   => 'required|numeric',
            'sbytes'=> 'required|numeric',
            'dbytes'=> 'required|numeric',
            // Add more validation as needed
        ]);

        try {
            $result = $this->detector->analyzeNetwork($request->all());
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 502);
        }

        return response()->json($result);
    }

    // ── Cyberbullying Scan ─────────────────────────────────────────────────────

    public function scanCyberbullying(Request $request): JsonResponse
    {
        // Accepts either raw text or structured stats
        if ($request->filled('text')) {
            try {
                $result = $this->detector->analyzeText($request->input('text'));
            } catch (\Exception $e) {
                return response()->json(['error' => $e->getMessage()], 502);
            }
        } else {
            $request->validate([
                'total_messages'   => 'required|numeric|min:0',
                'aggressive_count' => 'required|numeric|min:0',
                'intent_to_harm'   => 'required|numeric|between:0,1',
                'peerness'         => 'required|numeric|between:0,1',
            ]);

            try {
                $result = $this->detector->analyzeCyberbullying(
                    $request->input('total_messages'),
                    $request->input('aggressive_count'),
                    $request->input('intent_to_harm'),
                    $request->input('peerness'),
                );
            } catch (\Exception $e) {
                return response()->json(['error' => $e->getMessage()], 502);
            }
        }

        return response()->json($result);
    }

    // ── Batch Scan ─────────────────────────────────────────────────────────────

    public function scanBatch(Request $request): JsonResponse
    {
        $request->validate([
            'items'           => 'required|array|min:1|max:100',
            'items.*.type'    => 'required|in:url,network,cyberbullying',
            'items.*.data'    => 'required',
        ]);

        try {
            $results = $this->detector->analyzeBatch($request->input('items'));
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 502);
        }

        return response()->json($results);
    }

    // ── Health ─────────────────────────────────────────────────────────────────

    public function health(): JsonResponse
    {
        try {
            return response()->json($this->detector->health());
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 502);
        }
    }
}
