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

  // ---------------- Экран 1: список групп ----------------
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
        renderSubjectPicker(entry, payload);
      }).catch(function () {
        errorEl.textContent = 'Неверный пароль';
        document.getElementById('pass-submit').textContent = 'Показать оценки';
      });
    }
    document.getElementById('pass-submit').addEventListener('click', submit);
    passInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') submit(); });
  }

  // ---------------- Экран 2: список предметов группы ----------------
  function renderSubjectPicker(entry, payload) {
    var subjects = payload.subjects || [];
    var body = subjects.length
      ? '<div class="group-grid">' + subjects.map(function (subj, idx) {
        var total = subj.totalHours || 0;
        var pct = total > 0 ? Math.min(100, Math.round((subj.hoursPassed / total) * 100)) : 0;
        return '<button class="group-card" data-subject="' + idx + '"><h3>' + escapeHtml(subj.name) + '</h3>' +
          '<div class="progress-bar"><div style="width:' + pct + '%"></div></div>' +
          '<div class="meta">' + subj.hoursPassed + ' / ' + total + ' ч</div></button>';
      }).join('') + '</div>'
      : '<div class="empty">Предметы ещё не добавлены</div>';

    app.innerHTML =
      '<div class="back-row"><button id="back-btn" class="btn">&larr; Назад к группам</button></div>' +
      '<h1>' + escapeHtml(entry.name) + '</h1>' +
      body +
      '<p class="footnote">Данные опубликованы: ' + new Date(groupsData.publishedAt).toLocaleString('ru-RU') + '</p>';

    document.getElementById('back-btn').addEventListener('click', renderGroupList);
    Array.prototype.forEach.call(app.querySelectorAll('[data-subject]'), function (btn) {
      btn.addEventListener('click', function () {
        renderSubjectTabs(entry, payload, Number(btn.dataset.subject), 'final');
      });
    });
  }

  // ---------------- Экран 3: вкладки предмета ----------------
  function scoreCell(v) {
    if (!v) return '—';
    return v.s100 + ' <span class="grade5">(' + v.s5 + ')</span>';
  }

  function avgCell(v) { return (v === null || v === undefined) ? '—' : v; }

  function firstLine(s) { return (s || '').split('\n')[0]; }

  function kindTabHtml(subj, topics, scoresKey, avgKey, title) {
    if (!topics.length) {
      return '<div class="card"><div class="empty">Тем вида «' + title + '», отмеченных как «оценивается», пока нет.</div></div>';
    }
    var head = topics.map(function (t) { return '<th title="' + escapeHtml(firstLine(t)) + '">' + escapeHtml(firstLine(t).length > 16 ? firstLine(t).slice(0, 16) + '…' : firstLine(t)) + '</th>'; }).join('');
    var rows = subj.students.map(function (s) {
      var cells = s[scoresKey].map(function (v) { return '<td>' + scoreCell(v) + '</td>'; }).join('');
      return '<tr><td>' + escapeHtml(s.name) + '</td>' + cells + '<td><strong>' + avgCell(s[avgKey]) + '</strong></td></tr>';
    }).join('');
    return (
      '<div class="card">' +
      '<div class="table-wrap"><table><thead><tr><th>Студент</th>' + head + '<th>Среднее</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table></div>' +
      '<div class="footnote">В ячейках: балл по 100-балльной шкале, в скобках — оценка по 5-балльной. «Среднее» — среднее по 5-балльной шкале.</div>' +
      '</div>'
    );
  }

  function missingListText(names, label) {
    return names.length ? names.map(function (n) { return escapeHtml(firstLine(n)) + ' <span class="tag-muted">(' + label + ')</span>'; }).join(', ') : '';
  }

  function finalTabHtml(subj) {
    var srsEnabled = subj.srsEnabled !== false;
    var rows = subj.students.map(function (s) {
      var missingParts = [];
      var mlec = missingListText(s.missingLectureTopics, 'лекция');
      var mtask = missingListText(s.missingTaskTopics, 'задание');
      var msrs = srsEnabled ? missingListText(s.missingSrsTitles, 'СРС') : '';
      if (mlec) missingParts.push(mlec);
      if (mtask) missingParts.push(mtask);
      if (msrs) missingParts.push(msrs);
      var hasMissing = missingParts.length > 0;
      return (
        '<tr>' +
        '<td>' + escapeHtml(s.name) + '</td>' +
        '<td>' + (s.attendanceRate !== null ? s.attendanceRate + '%' : '—') + '</td>' +
        '<td>' + avgCell(s.lecturesAvg) + '</td>' +
        '<td>' + avgCell(s.tasksAvg) + '</td>' +
        (srsEnabled ? '<td>' + avgCell(s.srsAvg) + '</td>' : '') +
        '<td style="max-width:260px;white-space:normal;">' +
        '<strong>' + avgCell(s.final) + '</strong>' +
        (s.finalIsManual ? ' <span class="tag">ручная</span>' : '') +
        (hasMissing ? ' <span class="tag-warning">не всё оценено</span><div class="footnote" style="margin-top:4px;">Нет оценки: ' + missingParts.join(', ') + '</div>' : '') +
        '</td>' +
        '</tr>'
      );
    }).join('');

    return (
      '<div class="card">' +
      '<div class="table-wrap"><table><thead><tr><th>Студент</th><th>Посещаемость</th><th>Лекции</th><th>Задания</th>' +
      (srsEnabled ? '<th>СРС</th>' : '') + '<th>Итог</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table></div>' +
      '<div class="footnote">Итог — простое среднее по составляющим (посещаемость переводится в 5-балльную шкалу по тем же порогам, что и баллы). «Не всё оценено» значит, что по какой-то теме ещё нет оценки.</div>' +
      '</div>'
    );
  }

  function renderSubjectTabs(entry, payload, subjectIdx, tab) {
    var subj = payload.subjects[subjectIdx];
    var srsEnabled = subj.srsEnabled !== false;

    var tabs = [
      { id: 'lectures', label: 'Лекции' },
      { id: 'tasks', label: 'Задания' }
    ];
    if (srsEnabled) tabs.push({ id: 'srs', label: 'СРС' });
    tabs.push({ id: 'final', label: 'Итог' });

    var tabsHtml = '<div class="tabs">' + tabs.map(function (t) {
      return '<a href="#" data-tab="' + t.id + '" class="' + (t.id === tab ? 'active' : '') + '">' + t.label + '</a>';
    }).join('') + '</div>';

    var bodyHtml;
    if (tab === 'lectures') bodyHtml = kindTabHtml(subj, subj.lectureTopics, 'lectureScores', 'lecturesAvg', 'Лекция');
    else if (tab === 'tasks') bodyHtml = kindTabHtml(subj, subj.taskTopics, 'taskScores', 'tasksAvg', 'Задание');
    else if (tab === 'srs') bodyHtml = kindTabHtml(subj, subj.srsTitles, 'srsScores', 'srsAvg', 'СРС');
    else bodyHtml = finalTabHtml(subj);

    app.innerHTML =
      '<div class="back-row"><button id="back-btn" class="btn">&larr; Назад к предметам</button></div>' +
      '<h1>' + escapeHtml(subj.name) + '</h1>' +
      '<div class="hours">Часы по плану: ' + subj.hoursPassed + ' / ' + subj.totalHours + '</div>' +
      tabsHtml +
      bodyHtml;

    document.getElementById('back-btn').addEventListener('click', function () { renderSubjectPicker(entry, payload); });
    Array.prototype.forEach.call(app.querySelectorAll('[data-tab]'), function (a) {
      a.addEventListener('click', function (e) {
        e.preventDefault();
        renderSubjectTabs(entry, payload, subjectIdx, a.dataset.tab);
      });
    });
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
