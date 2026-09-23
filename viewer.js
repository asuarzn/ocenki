// Просмотр оценок студентами. Файл students_data.json содержит по одной зашифрованной
// записи на группу (AES-GCM, ключ выводится из пароля через PBKDF2) — расшифровка идёт
// прямо в браузере, сервер тут ни при чём. Без пароля группы прочитать данные нельзя.
(function () {
  var DATA_URL = 'students_data.json';
  var app = document.getElementById('app');
  var groupsData = null;

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function base64ToBuf(b64) {
    var binary = atob(b64);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  function deriveKey(password, saltBytes) {
    var enc = new TextEncoder();
    return crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey'])
      .then(function (keyMaterial) {
        return crypto.subtle.deriveKey(
          { name: 'PBKDF2', salt: saltBytes, iterations: 150000, hash: 'SHA-256' },
          keyMaterial,
          { name: 'AES-GCM', length: 256 },
          false,
          ['decrypt']
        );
      });
  }

  function decryptGroup(password, groupEntry) {
    var salt = new Uint8Array(base64ToBuf(groupEntry.salt));
    var iv = new Uint8Array(base64ToBuf(groupEntry.iv));
    var ciphertext = base64ToBuf(groupEntry.data);
    return deriveKey(password, salt).then(function (key) {
      return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ciphertext);
    }).then(function (plainBuf) {
      var dec = new TextDecoder();
      return JSON.parse(dec.decode(plainBuf));
    });
  }

  function renderGroupList() {
    if (!groupsData || !groupsData.groups.length) {
      app.innerHTML = '<div class="empty">Пока нет опубликованных групп. Обратитесь к преподавателю.</div>';
      return;
    }
    app.innerHTML =
      '<h1>Выберите группу</h1>' +
      '<p class="hint">Понадобится пароль группы, который выдал преподаватель.</p>' +
      '<div class="group-grid">' + groupsData.groups.map(function (g) {
        return '<button class="group-card" data-group="' + g.id + '">' + escapeHtml(g.name) + '</button>';
      }).join('') + '</div>';
    Array.prototype.forEach.call(app.querySelectorAll('[data-group]'), function (btn) {
      btn.addEventListener('click', function () { openPasswordPrompt(btn.dataset.group); });
    });
  }

  function openPasswordPrompt(groupId) {
    var entry = groupsData.groups.filter(function (g) { return g.id === groupId; })[0];
    app.innerHTML =
      '<div class="back-row"><button id="back-btn" class="btn">&larr; Назад к группам</button></div>' +
      '<h1>' + escapeHtml(entry.name) + '</h1>' +
      '<div class="pass-box">' +
      '<label for="pass-input">Пароль группы</label>' +
      '<input type="password" id="pass-input" autocomplete="off">' +
      '<button id="pass-submit" class="btn btn-primary">Показать оценки</button>' +
      '<div id="pass-error" class="error"></div>' +
      '</div>';
    document.getElementById('back-btn').addEventListener('click', renderGroupList);
    var passInput = document.getElementById('pass-input');
    passInput.focus();
    function submit() {
      var pass = passInput.value;
      if (!pass) return;
      var errorEl = document.getElementById('pass-error');
      errorEl.textContent = '';
      document.getElementById('pass-submit').textContent = 'Проверяю...';
      decryptGroup(pass, entry).then(function (payload) {
        renderGroupGrades(entry, payload);
      }).catch(function () {
        errorEl.textContent = 'Неверный пароль';
        document.getElementById('pass-submit').textContent = 'Показать оценки';
      });
    }
    document.getElementById('pass-submit').addEventListener('click', submit);
    passInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') submit(); });
  }

  function scoreCell(v) { return (v === null || v === undefined) ? '—' : v; }

  function firstLine(s) { return (s || '').split('\n')[0]; }

  function renderGroupGrades(entry, payload) {
    var subjectsHtml = (payload.subjects || []).map(function (subj) {
      var lectureHead = subj.lectureTopics.map(function (t) { return '<th>' + escapeHtml(firstLine(t)) + '</th>'; }).join('');
      var taskHead = subj.taskTopics.map(function (t) { return '<th>' + escapeHtml(firstLine(t)) + '</th>'; }).join('');
      var srsHead = subj.srsTitles.map(function (t) { return '<th>' + escapeHtml(t) + '</th>'; }).join('');
      var rows = subj.students.map(function (s) {
        var lecCells = s.lectureScores.map(function (v) { return '<td>' + scoreCell(v) + '</td>'; }).join('');
        var taskCells = s.taskScores.map(function (v) { return '<td>' + scoreCell(v) + '</td>'; }).join('');
        var srsCells = s.srsScores.map(function (v) { return '<td>' + scoreCell(v) + '</td>'; }).join('');
        return '<tr><td>' + escapeHtml(s.name) + '</td>' +
          '<td>' + (s.attendanceRate !== null ? s.attendanceRate + '%' : '—') + '</td>' +
          lecCells + taskCells + srsCells +
          '<td>' + scoreCell(s.lecturesAvg) + '</td>' +
          '<td>' + scoreCell(s.tasksAvg) + '</td>' +
          '<td>' + scoreCell(s.srsAvg) + '</td>' +
          '<td><strong>' + scoreCell(s.final) + '</strong>' + (s.finalIsManual ? ' <span class="tag">ручная</span>' : '') + '</td>' +
          '</tr>';
      }).join('');
      return '<div class="subject-card">' +
        '<h2>' + escapeHtml(subj.name) + '</h2>' +
        '<div class="hours">Часы по плану: ' + subj.hoursPassed + ' / ' + subj.totalHours + '</div>' +
        '<div class="table-wrap"><table><thead><tr><th>Студент</th><th>Посещаемость</th>' +
        lectureHead + taskHead + srsHead +
        '<th>Лекции ср.</th><th>Задания ср.</th><th>СРС ср.</th><th>Итог</th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table></div>' +
        '</div>';
    }).join('');

    app.innerHTML =
      '<div class="back-row"><button id="back-btn" class="btn">&larr; Назад к группам</button></div>' +
      '<h1>' + escapeHtml(entry.name) + '</h1>' +
      (payload.subjects && payload.subjects.length ? subjectsHtml : '<div class="empty">Предметы ещё не добавлены</div>') +
      '<p class="footnote">Данные опубликованы: ' + new Date(groupsData.publishedAt).toLocaleString('ru-RU') + '</p>';
    document.getElementById('back-btn').addEventListener('click', renderGroupList);
  }

  if (!window.crypto || !window.crypto.subtle) {
    app.innerHTML = '<div class="empty">Этот браузер не поддерживает нужный режим шифрования. Попробуйте открыть страницу в Chrome, Edge или Firefox.</div>';
    return;
  }

  fetch(DATA_URL, { cache: 'no-store' })
    .then(function (r) {
      if (!r.ok) throw new Error('not found');
      return r.json();
    })
    .then(function (data) {
      groupsData = data;
      renderGroupList();
    })
    .catch(function () {
      app.innerHTML = '<div class="empty">Не удалось загрузить данные оценок. Обратитесь к преподавателю.</div>';
    });
})();
