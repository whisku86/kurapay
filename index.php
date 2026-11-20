<?php
declare(strict_types=1);
require_once __DIR__ . '/security.php';
require_once __DIR__ . '/db.php';

enforceSessionSecurity();
$pdo = getDB();

$isLoggedIn = !empty($_SESSION['user_id']);
$userId     = $isLoggedIn ? (int)$_SESSION['user_id'] : null;
$role       = $_SESSION['role'] ?? 'voter';
$csrfToken  = $_SESSION['csrf_token'] ?? '';
$user       = null;
$polls      = [];
$freeLocks  = [];
$devAdmins  = [];

if ($isLoggedIn) {
    $stmt = $pdo->prepare('SELECT id, full_name, email, phone, role, wallet_balance FROM users WHERE id = ?');
    $stmt->execute([$userId]);
    $user = $stmt->fetch();

    if (!$user) {
        destroySession();
        header('Location: index.php');
        exit;
    }

    // Fetch active polls & all polls for admin
    $pollSql = ($role === 'admin')
        ? 'SELECT * FROM polls ORDER BY created_at DESC'
        : 'SELECT * FROM polls WHERE is_active = 1 ORDER BY created_at DESC';
    $polls = $pdo->query($pollSql)->fetchAll();

    // Fetch candidates with live percentage calculation
    $candStmt = $pdo->prepare(
        'SELECT id, name, manifesto, vote_count,
                ROUND(COALESCE(vote_count * 100.0 / NULLIF(SUM(vote_count) OVER (), 0), 0), 1) AS percentage
         FROM candidates
         WHERE poll_id = ?
         ORDER BY vote_count DESC, id ASC'
    );

    foreach ($polls as &$poll) {
        $candStmt->execute([$poll['id']]);
        $poll['candidates'] = $candStmt->fetchAll();
        $poll['total_votes'] = array_sum(array_column($poll['candidates'], 'vote_count'));
    }
    unset($poll);

    // Fetch free poll locks for current voter
    $lockStmt = $pdo->prepare('SELECT poll_id FROM free_poll_locks WHERE user_id = ?');
    $lockStmt->execute([$userId]);
    $freeLocks = array_flip($lockStmt->fetchAll(PDO::FETCH_COLUMN));

    // Fetch developer-provisioned admins (read-only registry for Admin Studio)
    if ($role === 'admin') {
        $devAdmins = $pdo->query(
            "SELECT id, full_name, email, phone, created_at FROM users WHERE role = 'admin' ORDER BY id ASC"
        )->fetchAll();
    }
}

function e(string $val): string
{
    return htmlspecialchars($val, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>KuraPay — Secure Paid & Free Polling Platform</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet" />
  <style>
    body { font-family: 'Inter', sans-serif; }
  </style>
</head>
<body class="bg-slate-50 text-slate-900 min-h-screen flex flex-col">

<?php if (!$isLoggedIn): ?>
  <!-- ==================== AUTHENTICATION VIEW ==================== -->
  <div class="min-h-screen flex items-center justify-center p-4 bg-gradient-to-br from-emerald-950 via-slate-900 to-slate-950">
    <div class="w-full max-w-md bg-white rounded-2xl shadow-2xl border border-slate-200 overflow-hidden">
      <div class="p-6 bg-emerald-600 text-white">
        <div class="flex items-center justify-between">
          <span class="text-2xl font-extrabold tracking-tight">KuraPay</span>
          <span class="text-xs font-semibold uppercase tracking-wider bg-emerald-800/70 px-2.5 py-1 rounded-full">
            Session Protected
          </span>
        </div>
        <p class="text-emerald-100 text-sm mt-1">
          Log in, fund your wallet via M-Pesa/Paystack, and vote with real-time percentage results.
        </p>
      </div>

      <!-- Auth Tabs -->
      <div class="grid grid-cols-2 border-b border-slate-200 text-sm font-semibold">
        <button id="tab-login" onclick="switchAuthTab('login')" class="py-3 text-emerald-700 border-b-2 border-emerald-600 bg-emerald-50/50">
          Sign In
        </button>
        <button id="tab-register" onclick="switchAuthTab('register')" class="py-3 text-slate-500 hover:text-slate-800">
          Voter Registration
        </button>
      </div>

      <div class="p-6">
        <div id="auth-alert" class="hidden mb-4 p-3 rounded-lg text-sm font-medium"></div>

        <!-- Login Form -->
        <form id="login-form" onsubmit="handleLogin(event)" class="space-y-4">
          <div>
            <label class="block text-xs font-semibold uppercase text-slate-600 mb-1">Email Address</label>
            <input type="email" id="login-email" required placeholder="you@example.co.ke"
                   class="w-full px-3.5 py-2.5 rounded-lg border border-slate-300 focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 outline-none text-sm" />
          </div>
          <div>
            <label class="block text-xs font-semibold uppercase text-slate-600 mb-1">Password</label>
            <input type="password" id="login-password" required placeholder="••••••••"
                   class="w-full px-3.5 py-2.5 rounded-lg border border-slate-300 focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 outline-none text-sm" />
          </div>
          <button type="submit" class="w-full py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white font-semibold text-sm transition shadow-sm">
            Sign In Securely
          </button>
          <p class="text-xs text-slate-500 text-center pt-1">
            Admin accounts are provisioned strictly by the system developer.
          </p>
        </form>

        <!-- Voter-Only Registration Form -->
        <form id="register-form" onsubmit="handleRegister(event)" class="hidden space-y-3.5">
          <div>
            <label class="block text-xs font-semibold uppercase text-slate-600 mb-1">Full Name</label>
            <input type="text" id="reg-name" required placeholder="Wanjiku Kamau"
                   class="w-full px-3.5 py-2.5 rounded-lg border border-slate-300 focus:ring-2 focus:ring-emerald-500 outline-none text-sm" />
          </div>
          <div>
            <label class="block text-xs font-semibold uppercase text-slate-600 mb-1">Email Address</label>
            <input type="email" id="reg-email" required placeholder="wanjiku@example.co.ke"
                   class="w-full px-3.5 py-2.5 rounded-lg border border-slate-300 focus:ring-2 focus:ring-emerald-500 outline-none text-sm" />
          </div>
          <div>
            <label class="block text-xs font-semibold uppercase text-slate-600 mb-1">M-Pesa Phone (2547...)</label>
            <input type="tel" id="reg-phone" required placeholder="254712345678"
                   class="w-full px-3.5 py-2.5 rounded-lg border border-slate-300 focus:ring-2 focus:ring-emerald-500 outline-none text-sm" />
          </div>
          <div>
            <label class="block text-xs font-semibold uppercase text-slate-600 mb-1">Password (Min 8 chars)</label>
            <input type="password" id="reg-password" minlength="8" required placeholder="••••••••"
                   class="w-full px-3.5 py-2.5 rounded-lg border border-slate-300 focus:ring-2 focus:ring-emerald-500 outline-none text-sm" />
          </div>
          <button type="submit" class="w-full py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white font-semibold text-sm transition">
            Create Voter Account
          </button>
        </form>
      </div>
    </div>
  </div>

<?php else: ?>
  <!-- ==================== AUTHENTICATED DASHBOARD ==================== -->
  <header class="bg-white border-b border-slate-200 sticky top-0 z-30">
    <div class="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between gap-4">
      <div class="flex items-center gap-3">
        <span class="text-xl font-extrabold text-emerald-700 tracking-tight">KuraPay</span>
        <?php if ($role === 'admin'): ?>
          <span class="text-xs font-bold uppercase px-2.5 py-0.5 rounded-full bg-amber-100 text-amber-800 border border-amber-300">
            Developer Admin
          </span>
        <?php else: ?>
          <span class="text-xs font-semibold uppercase px-2.5 py-0.5 rounded-full bg-emerald-100 text-emerald-800">
            Verified Voter
          </span>
        <?php endif; ?>
      </div>

      <div class="flex items-center gap-3">
        <!-- Wallet Pill -->
        <button onclick="openTopupModal()" class="flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-emerald-50 hover:bg-emerald-100 border border-emerald-200 text-emerald-900 text-sm font-semibold transition">
          <span>Wallet: KES <strong id="wallet-balance"><?= number_format((float)$user['wallet_balance'], 2) ?></strong></span>
          <span class="text-xs bg-emerald-600 text-white px-2 py-0.5 rounded-full">+ Top Up</span>
        </button>

        <span class="hidden sm:inline text-sm text-slate-600 font-medium"><?= e($user['full_name']) ?></span>

        <button onclick="handleLogout()" class="px-3 py-1.5 rounded-lg border border-slate-300 hover:bg-slate-100 text-xs font-semibold text-slate-700 transition">
          Logout
        </button>
      </div>
    </div>
  </header>

  <main class="max-w-6xl mx-auto w-full px-4 py-8 flex-1 space-y-8">
    <!-- Global Notification Banner -->
    <div id="toast-banner" class="hidden p-4 rounded-xl border text-sm font-medium shadow-sm"></div>

    <?php if ($role === 'admin'): ?>
      <!-- ==================== ADMIN STUDIO ==================== -->
      <section class="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 space-y-6">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 pb-4">
          <div>
            <h2 class="text-lg font-bold text-slate-900">Admin Studio — Create Poll & Candidates</h2>
            <p class="text-xs text-slate-500">Protected by HttpOnly Session Token + X-CSRF-Token verification.</p>
          </div>
          <span class="text-xs font-mono bg-slate-100 text-slate-700 px-2.5 py-1 rounded">
            Role: <?= e($role) ?>
          </span>
        </div>

        <form id="create-poll-form" onsubmit="handleCreatePoll(event)" class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label class="block text-xs font-semibold uppercase text-slate-600 mb-1">Poll Title</label>
            <input type="text" id="poll-title" required placeholder="e.g., Nairobi Tech Awards 2026"
                   class="w-full px-3.5 py-2 rounded-lg border border-slate-300 text-sm focus:ring-2 focus:ring-emerald-500 outline-none" />
          </div>

          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block text-xs font-semibold uppercase text-slate-600 mb-1">Poll Type</label>
              <select id="poll-type" onchange="toggleVotePriceField()"
                      class="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm bg-white focus:ring-2 focus:ring-emerald-500 outline-none">
                <option value="paid">Paid (Multi-Vote by Wallet)</option>
                <option value="free">Free (1 Vote Per User)</option>
              </select>
            </div>
            <div id="vote-price-wrapper">
              <label class="block text-xs font-semibold uppercase text-slate-600 mb-1">Cost Per Vote (KES)</label>
              <input type="number" id="poll-price" min="1" step="1" value="10"
                     class="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm focus:ring-2 focus:ring-emerald-500 outline-none" />
            </div>
          </div>

          <div class="md:col-span-2">
            <label class="block text-xs font-semibold uppercase text-slate-600 mb-1">Description</label>
            <input type="text" id="poll-desc" placeholder="Brief rules or category overview..."
                   class="w-full px-3.5 py-2 rounded-lg border border-slate-300 text-sm focus:ring-2 focus:ring-emerald-500 outline-none" />
          </div>

          <div class="md:col-span-2 space-y-2">
            <div class="flex items-center justify-between">
              <label class="block text-xs font-semibold uppercase text-slate-600">Candidates</label>
              <button type="button" onclick="addCandidateInput()" class="text-xs font-semibold text-emerald-700 hover:underline">
                + Add Another Candidate
              </button>
            </div>
            <div id="candidate-inputs" class="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <input type="text" name="candidate_name[]" required placeholder="Candidate 1 Name"
                     class="px-3.5 py-2 rounded-lg border border-slate-300 text-sm" />
              <input type="text" name="candidate_name[]" required placeholder="Candidate 2 Name"
                     class="px-3.5 py-2 rounded-lg border border-slate-300 text-sm" />
            </div>
          </div>

          <div class="md:col-span-2 flex justify-end">
            <button type="submit" class="px-5 py-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-sm font-semibold transition">
              Publish Poll & Candidates
            </button>
          </div>
        </form>

        <!-- Developer-Provisioned Admin Registry (Read-Only) -->
        <div class="pt-4 border-t border-slate-100">
          <h3 class="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2">
            Developer-Provisioned Admin Registry (CLI-Seeded Only)
          </h3>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs border border-slate-200 rounded-lg overflow-hidden">
              <thead class="bg-slate-50 text-slate-600">
                <tr>
                  <th class="px-3 py-2">Admin Name</th>
                  <th class="px-3 py-2">Email</th>
                  <th class="px-3 py-2">Phone</th>
                  <th class="px-3 py-2">Provisioned</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-200">
                <?php foreach ($devAdmins as $adm): ?>
                  <tr>
                    <td class="px-3 py-2 font-medium"><?= e($adm['full_name']) ?></td>
                    <td class="px-3 py-2 font-mono"><?= e($adm['email']) ?></td>
                    <td class="px-3 py-2"><?= e($adm['phone']) ?></td>
                    <td class="px-3 py-2 text-slate-500"><?= e($adm['created_at']) ?></td>
                  </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        </div>
      </section>
    <?php endif; ?>

    <!-- ==================== POLLS & LIVE PERCENTAGE LEADERBOARDS ==================== -->
    <section class="space-y-4">
      <div class="flex items-center justify-between">
        <h1 class="text-xl font-extrabold text-slate-900">Active Polls & Live Results</h1>
        <span class="text-xs text-slate-500">Results update in percentages (%) after every verified vote</span>
      </div>

      <?php if (empty($polls)): ?>
        <div class="bg-white rounded-2xl border border-slate-200 p-10 text-center text-slate-500 text-sm">
          No active polls available right now.
        </div>
      <?php else: ?>
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <?php foreach ($polls as $poll):
            $isPaid      = ($poll['poll_type'] === 'paid');
            $alreadyPaid = false;
            $lockedFree  = (!$isPaid && isset($freeLocks[$poll['id']]));
            $votePrice   = (float)$poll['vote_price'];
          ?>
            <article class="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 flex flex-col justify-between space-y-5">
              <div>
                <div class="flex items-start justify-between gap-3">
                  <div>
                    <h2 class="text-lg font-bold text-slate-900"><?= e($poll['title']) ?></h2>
                    <?php if (!empty($poll['description'])): ?>
                      <p class="text-sm text-slate-600 mt-1"><?= e($poll['description']) ?></p>
                    <?php endif; ?>
                  </div>

                  <?php if ($isPaid): ?>
                    <span class="shrink-0 text-xs font-bold px-3 py-1 rounded-full bg-emerald-100 text-emerald-800">
                      KES <?= number_format($votePrice, 0) ?> / vote · Unlimited
                    </span>
                  <?php else: ?>
                    <span class="shrink-0 text-xs font-bold px-3 py-1 rounded-full bg-sky-100 text-sky-800">
                      Free · 1 Vote Only
                    </span>
                  <?php endif; ?>
                </div>

                <!-- Candidates List with Live Percentage Bars -->
                <div class="mt-5 space-y-3.5">
                  <?php foreach ($poll['candidates'] as $cand):
                    $pct = (float)$cand['percentage'];
                  ?>
                    <div class="p-3.5 rounded-xl border border-slate-200 bg-slate-50/70 space-y-2.5">
                      <div class="flex items-center justify-between gap-2">
                        <div>
                          <div class="font-semibold text-slate-900 text-sm"><?= e($cand['name']) ?></div>
                          <?php if (!empty($cand['manifesto'])): ?>
                            <div class="text-xs text-slate-500"><?= e($cand['manifesto']) ?></div>
                          <?php endif; ?>
                        </div>
                        <div class="text-right">
                          <span class="text-base font-extrabold text-emerald-700"><?= number_format($pct, 1) ?>%</span>
                          <span class="block text-[11px] text-slate-500"><?= number_format((int)$cand['vote_count']) ?> votes</span>
                        </div>
                      </div>

                      <!-- Percentage Progress Bar -->
                      <div class="w-full h-2.5 bg-slate-200 rounded-full overflow-hidden">
                        <div class="h-full bg-emerald-600 rounded-full transition-all duration-500" style="width: <?= min(100, max(0, $pct)) ?>%"></div>
                      </div>

                      <!-- Voting Action Controls -->
                      <?php if ($lockedFree): ?>
                        <div class="text-xs font-semibold text-sky-700 bg-sky-50 border border-sky-200 px-3 py-1.5 rounded-lg">
                          You have already cast your single free vote on this poll.
                        </div>
                      <?php elseif ($isPaid): ?>
                        <div class="flex items-center gap-2 pt-1">
                          <input type="number" id="qty-<?= (int)$poll['id'] ?>-<?= (int)$cand['id'] ?>"
                                 min="1" value="1"
                                 class="w-20 px-2.5 py-1.5 rounded-lg border border-slate-300 text-xs font-semibold bg-white" />
                          <button type="button"
                                  onclick="castVote(<?= (int)$poll['id'] ?>, <?= (int)$cand['id'] ?>, true, <?= $votePrice ?>)"
                                  class="flex-1 py-1.5 px-3 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold transition">
                            Pay & Vote
                          </button>
                        </div>
                      <?php else: ?>
                        <div class="pt-1">
                          <button type="button"
                                  onclick="castVote(<?= (int)$poll['id'] ?>, <?= (int)$cand['id'] ?>, false, 0)"
                                  class="w-full py-1.5 px-3 rounded-lg bg-sky-600 hover:bg-sky-700 text-white text-xs font-semibold transition">
                            Cast Free Vote (1 Allowed)
                          </button>
                        </div>
                      <?php endif; ?>
                    </div>
                  <?php endforeach; ?>
                </div>
              </div>

              <div class="pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
                <span>Total Votes Cast: <strong><?= number_format((int)$poll['total_votes']) ?></strong></span>
                <span>Poll #<?= (int)$poll['id'] ?></span>
              </div>
            </article>
          <?php endforeach; ?>
        </div>
      <?php endif; ?>
    </section>
  </main>

  <!-- ==================== M-PESA / PAYSTACK TOP-UP MODAL ==================== -->
  <div id="topup-modal" class="hidden fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4">
    <div class="bg-white rounded-2xl max-w-md w-full p-6 shadow-2xl border border-slate-200 space-y-4">
      <div class="flex items-center justify-between">
        <h3 class="text-lg font-bold text-slate-900">Top Up Voting Wallet</h3>
        <button onclick="closeTopupModal()" class="text-slate-400 hover:text-slate-700 text-xl font-bold">&times;</button>
      </div>
      <p class="text-xs text-slate-600">
        Enter your M-Pesa number and deposit amount. Your wallet is credited automatically once the payment webhook confirms.
      </p>
      <form onsubmit="handleTopup(event)" class="space-y-3.5">
        <div>
          <label class="block text-xs font-semibold uppercase text-slate-600 mb-1">M-Pesa Phone Number</label>
          <input type="tel" id="topup-phone" required value="<?= e($user['phone']) ?>"
                 class="w-full px-3.5 py-2 rounded-lg border border-slate-300 text-sm" />
        </div>
        <div>
          <label class="block text-xs font-semibold uppercase text-slate-600 mb-1">Amount (KES)</label>
          <input type="number" id="topup-amount" min="10" step="10" value="100" required
                 class="w-full px-3.5 py-2 rounded-lg border border-slate-300 text-sm" />
        </div>
        <button type="submit" class="w-full py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-sm font-semibold transition">
          Send M-Pesa STK Push
        </button>
      </form>
    </div>
  </div>
<?php endif; ?>

<script>
  // Server-generated anti-CSRF token bound to the current HttpOnly session
  const CSRF_TOKEN = <?= json_encode($csrfToken, JSON_HEX_TAG | JSON_HEX_AMP) ?>;

  function showBanner(message, isError = false) {
    const el = document.getElementById('toast-banner');
    if (!el) return;
    el.textContent = message;
    el.className = `p-4 rounded-xl border text-sm font-medium shadow-sm ${
      isError
        ? 'bg-rose-50 border-rose-200 text-rose-800'
        : 'bg-emerald-50 border-emerald-200 text-emerald-800'
    }`;
    el.classList.remove('hidden');
  }

  function switchAuthTab(tab) {
    const loginForm = document.getElementById('login-form');
    const regForm   = document.getElementById('register-form');
    const tabLogin  = document.getElementById('tab-login');
    const tabReg    = document.getElementById('tab-register');

    if (tab === 'login') {
      loginForm.classList.remove('hidden');
      regForm.classList.add('hidden');
      tabLogin.className = 'py-3 text-emerald-700 border-b-2 border-emerald-600 bg-emerald-50/50';
      tabReg.className   = 'py-3 text-slate-500 hover:text-slate-800';
    } else {
      regForm.classList.remove('hidden');
      loginForm.classList.add('hidden');
      tabReg.className   = 'py-3 text-emerald-700 border-b-2 border-emerald-600 bg-emerald-50/50';
      tabLogin.className = 'py-3 text-slate-500 hover:text-slate-800';
    }
  }

  async function apiPost(url, payload) {
    const res = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin', // Always send HttpOnly KURAPAY_SID cookie
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': CSRF_TOKEN
      },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Request failed');
    return data;
  }

  async function handleLogin(e) {
    e.preventDefault();
    try {
      await apiPost('auth.php?action=login', {
        email: document.getElementById('login-email').value,
        password: document.getElementById('login-password').value
      });
      window.location.reload();
    } catch (err) {
      const alertBox = document.getElementById('auth-alert');
      alertBox.textContent = err.message;
      alertBox.className = 'mb-4 p-3 rounded-lg text-sm font-medium bg-rose-50 text-rose-800 border border-rose-200';
      alertBox.classList.remove('hidden');
    }
  }

  async function handleRegister(e) {
    e.preventDefault();
    try {
      await apiPost('auth.php?action=register', {
        full_name: document.getElementById('reg-name').value,
        email: document.getElementById('reg-email').value,
        phone: document.getElementById('reg-phone').value,
        password: document.getElementById('reg-password').value
      });
      window.location.reload();
    } catch (err) {
      const alertBox = document.getElementById('auth-alert');
      alertBox.textContent = err.message;
      alertBox.className = 'mb-4 p-3 rounded-lg text-sm font-medium bg-rose-50 text-rose-800 border border-rose-200';
      alertBox.classList.remove('hidden');
    }
  }

  async function handleLogout() {
    await apiPost('auth.php?action=logout', {});
    window.location.reload();
  }

  async function castVote(pollId, candidateId, isPaid, votePrice) {
    const qtyInput = document.getElementById(`qty-${pollId}-${candidateId}`);
    const quantity = isPaid && qtyInput ? Math.max(1, parseInt(qtyInput.value, 10) || 1) : 1;

    try {
      const result = await apiPost('vote.php', {
        poll_id: pollId,
        candidate_id: candidateId,
        quantity: quantity
      });
      showBanner(`Vote recorded! Cast ${result.quantity} vote(s). Refreshing percentages...`);
      setTimeout(() => window.location.reload(), 700);
    } catch (err) {
      showBanner(err.message, true);
      if (err.message.toLowerCase().includes('balance')) {
        openTopupModal();
      }
    }
  }

  function toggleVotePriceField() {
    const type = document.getElementById('poll-type').value;
    document.getElementById('vote-price-wrapper').style.display = (type === 'free') ? 'none' : 'block';
  }

  function addCandidateInput() {
    const container = document.getElementById('candidate-inputs');
    const count = container.querySelectorAll('input').length + 1;
    const input = document.createElement('input');
    input.type = 'text';
    input.name = 'candidate_name[]';
    input.required = true;
    input.placeholder = `Candidate ${count} Name`;
    input.className = 'px-3.5 py-2 rounded-lg border border-slate-300 text-sm';
    container.appendChild(input);
  }

  async function handleCreatePoll(e) {
    e.preventDefault();
    const candidates = Array.from(document.querySelectorAll('input[name="candidate_name[]"]'))
      .map(el => el.value.trim())
      .filter(Boolean);

    try {
      await apiPost('admin_polls.php', {
        title: document.getElementById('poll-title').value,
        description: document.getElementById('poll-desc').value,
        poll_type: document.getElementById('poll-type').value,
        vote_price: document.getElementById('poll-price').value,
        candidates: candidates
      });
      window.location.reload();
    } catch (err) {
      showBanner(err.message, true);
    }
  }

  function openTopupModal() {
    document.getElementById('topup-modal').classList.remove('hidden');
  }

  function closeTopupModal() {
    document.getElementById('topup-modal').classList.add('hidden');
  }

  async function handleTopup(e) {
    e.preventDefault();
    try {
      const res = await apiPost('topup.php', {
        phone: document.getElementById('topup-phone').value,
        amount: document.getElementById('topup-amount').value
      });
      closeTopupModal();
      showBanner(res.message || 'M-Pesa STK Push sent! Enter your PIN on your phone.');
    } catch (err) {
      showBanner(err.message, true);
    }
  }
</script>
</body>
</html>