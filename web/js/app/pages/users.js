/* Wire_Ghost — User Management (API-driven, no mock) */

WG.renderUsers = function() {
  var currentUser = WG.currentUser();
  var isOwner = currentUser && currentUser.role === 'owner';
  var esc = WG.escHtml;

  // Owner-only page. The router gates this too, but guarding here prevents a
  // stray /api/auth/users/ fetch during any race where render still fires.
  if (!isOwner) {
    return '<div class="panel" style="max-width:700px;margin:40px auto;"><div class="panel-body"><div class="panel-empty"><div class="icon">&#128274;</div>Owner access required.</div></div></div>';
  }

  var users = WG.getCached('users', '/auth/users/');

  // Background refresh
  WG.fetchData('/auth/users/', 'users').then(function(data) {
    if (data && data.length && WG.state.currentPage === 'users') {
      WG._cache['users'] = data; WG._cacheTime['users'] = Date.now();
      var main = document.getElementById('mainContent');
      if (main && !document.querySelector(".modal-overlay.active")) main.innerHTML = WG.renderUsers();
    }
  });

  var roleCounts = {};
  users.forEach(function(u) { roleCounts[u.role] = (roleCounts[u.role] || 0) + 1; });
  var activeCount = users.filter(function(u) { return u.status === 'active'; }).length;

  return '' +
    '<div class="page-header">' +
      '<div class="page-header-left"><h1>Users</h1><p>' + users.length + ' accounts &mdash; ' + activeCount + ' active</p></div>' +
      '<div class="page-header-actions">' +
        (isOwner ? '<button class="btn btn-primary" onclick="WG.openUserModal()"><span>+</span> Add User</button>' : '') +
      '</div>' +
    '</div>' +

    '<div class="stats-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:20px;">' +
      '<div class="stat-card"><div class="stat-label">Total Users</div><div class="stat-value">' + users.length + '</div></div>' +
      '<div class="stat-card"><div class="stat-label">Owner</div><div class="stat-value">' + (roleCounts.owner || 0) + '</div></div>' +
      '<div class="stat-card"><div class="stat-label">Engineers</div><div class="stat-value">' + (roleCounts.engineer || 0) + '</div></div>' +
      '<div class="stat-card"><div class="stat-label">Viewers</div><div class="stat-value">' + (roleCounts.viewer || 0) + '</div></div>' +
    '</div>' +

    '<div class="filters-bar"><input class="filter-input" placeholder="Search users..." id="userSearch" oninput="WG.filterUsers()"></div>' +

    (users.length === 0 ?
      '<div class="panel"><div class="panel-empty"><div class="icon">&#128100;</div>No users found. ' + (isOwner ? 'Click "Add User" to create one.' : 'Contact the Owner.') + '</div></div>'
    :
      '<div class="panel"><table class="data-table" id="usersTable"><thead><tr><th>User</th><th>Email</th><th>Role</th><th>Status</th><th>Last Login</th>' +
      (isOwner ? '<th></th>' : '') +
      '</tr></thead><tbody>' +
      users.map(function(u) {
        if (u.role && u.role !== 'owner' && u.role !== 'engineer' && u.role !== 'viewer') {
          console.warn('Unknown user role:', u.role, '— migrate or normalize this row.');
        }
        var roleBadge = u.role === 'owner' ? 'critical' : u.role === 'engineer' ? 'medium' : 'info';
        var isOwnerRow = u.role === 'owner';
        return '<tr data-search="' + esc((u.name + ' ' + u.username + ' ' + u.email + ' ' + u.role).toLowerCase()) + '">' +
          '<td><div style="display:flex;align-items:center;gap:10px;">' +
            '<div class="user-avatar-sm">' + esc(u.avatar) + '</div>' +
            '<div><div style="font-weight:600;color:var(--text-bright);">' + esc(u.name) + '</div>' +
            '<div class="mono" style="font-size:0.7rem;">' + esc(u.username) + '</div></div>' +
          '</div></td>' +
          '<td class="mono" style="font-size:0.78rem;">' + esc(u.email) + '</td>' +
          '<td><span class="sev-badge ' + roleBadge + '">' + esc(u.role) + '</span></td>' +
          '<td><span class="status-badge ' + (u.status === 'active' ? 'completed' : 'cancelled') + '"><span class="dot"></span> ' + esc(u.status) + '</span></td>' +
          '<td class="mono">' + (u.last_login ? WG.timeAgo(u.last_login) : 'Never') + '</td>' +
          (isOwner ? '<td style="text-align:right;">' +
            (isOwnerRow ? '<span style="font-size:0.7rem;color:var(--text-dim);">Protected</span>' :
              '<button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();WG.openUserModal(\'' + u.id + '\')">Edit</button>' +
              (u.id !== currentUser.id ? ' <button class="btn btn-ghost btn-sm" style="color:var(--critical);" onclick="event.stopPropagation();WG.deleteUser(\'' + u.id + '\')">Delete</button>' : '')
            ) +
          '</td>' : '') +
        '</tr>';
      }).join('') +
      '</tbody></table></div>'
    ) +

    '<div class="modal-overlay" id="userModal"><div class="modal"><div class="modal-header"><h2 id="userModalTitle">Add User</h2><p id="userModalDesc">Create a new user account</p></div>' +
    '<div class="modal-body">' +
      '<input type="hidden" id="userEditId" value="">' +
      '<div class="form-row"><div class="form-group"><label class="form-label">Full Name</label><input class="form-input" id="userName" placeholder="Jane Doe"></div>' +
      '<div class="form-group"><label class="form-label">Username</label><input class="form-input" id="userUsername" placeholder="jdoe"></div></div>' +
      '<div class="form-row"><div class="form-group"><label class="form-label">Email</label><input class="form-input" id="userEmail" type="email" placeholder="jane@company.com"></div>' +
      '<div class="form-group"><label class="form-label">Role</label><select class="form-select" id="userRole"><option value="viewer">Viewer</option><option value="engineer">Engineer</option></select></div></div>' +
      '<div class="form-row"><div class="form-group"><label class="form-label">Password</label><input class="form-input" id="userPass" type="password" placeholder="Enter password"></div>' +
      '<div class="form-group"><label class="form-label">Status</label><select class="form-select" id="userStatus"><option value="active">Active</option><option value="disabled">Disabled</option></select></div></div>' +
      '<div id="userModalError" style="display:none;color:var(--critical);font-size:0.82rem;"></div>' +
    '</div>' +
    '<div class="modal-footer"><button class="btn btn-secondary" onclick="WG.closeModal(\'userModal\')">Cancel</button><button class="btn btn-primary" id="userSaveBtn" onclick="WG.saveUser()">Save User</button></div></div></div>';
};

WG.filterUsers = function() {
  var search = (document.getElementById('userSearch').value || '').toLowerCase();
  document.querySelectorAll('#usersTable tbody tr').forEach(function(tr) {
    tr.style.display = (!search || tr.dataset.search.includes(search)) ? '' : 'none';
  });
};

WG.openUserModal = function(userId) {
  var title = document.getElementById('userModalTitle');
  var desc = document.getElementById('userModalDesc');
  var err = document.getElementById('userModalError');
  if (err) err.style.display = 'none';

  if (userId) {
    var users = WG._cache['users'] || [];
    var user = users.find(function(u) { return u.id === userId; });
    if (!user) return;
    title.textContent = 'Edit User';
    desc.textContent = 'Modify user account';
    document.getElementById('userEditId').value = userId;
    document.getElementById('userName').value = user.name;
    document.getElementById('userUsername').value = user.username;
    document.getElementById('userEmail').value = user.email;
    document.getElementById('userRole').value = user.role;
    document.getElementById('userStatus').value = user.status;
    document.getElementById('userPass').value = '';
    document.getElementById('userPass').placeholder = 'Leave blank to keep current';
  } else {
    title.textContent = 'Add User';
    desc.textContent = 'Create a new user account';
    document.getElementById('userEditId').value = '';
    document.getElementById('userName').value = '';
    document.getElementById('userUsername').value = '';
    document.getElementById('userEmail').value = '';
    document.getElementById('userRole').value = 'viewer';
    document.getElementById('userStatus').value = 'active';
    document.getElementById('userPass').value = '';
    document.getElementById('userPass').placeholder = 'Enter password';
  }
  WG.openModal('userModal');
};

WG.saveUser = function() {
  var editId = document.getElementById('userEditId').value;
  var name = document.getElementById('userName').value.trim();
  var username = document.getElementById('userUsername').value.trim();
  var email = document.getElementById('userEmail').value.trim();
  var role = document.getElementById('userRole').value;
  var status = document.getElementById('userStatus').value;
  var pass = document.getElementById('userPass').value;
  var err = document.getElementById('userModalError');
  var btn = document.getElementById('userSaveBtn');

  if (!name || !username || !email) { err.textContent = 'Name, username, and email required'; err.style.display = 'block'; return; }
  if (!editId && !pass) { err.textContent = 'Password required for new users'; err.style.display = 'block'; return; }

  btn.disabled = true;
  btn.textContent = 'Saving...';
  err.style.display = 'none';

  var data = { name: name, username: username, email: email, role: role, status: status };
  if (pass) data.password = pass;

  if (editId) {
    // Update existing user
    WG.api('/auth/users/' + editId + '/', { method: 'PUT', body: JSON.stringify(data) }).then(function(res) {
      btn.disabled = false;
      btn.textContent = 'Save User';
      if (res && !res.error) {
        WG.toast('User updated: ' + name, 'success');
        WG.invalidateCache('users');
        WG.closeModal('userModal');
        WG.render();
      } else {
        err.textContent = (res && res.error) || 'Update failed';
        err.style.display = 'block';
      }
    });
  } else {
    // Create new user
    WG.api('/auth/users/create/', { method: 'POST', body: JSON.stringify(data) }).then(function(res) {
      btn.disabled = false;
      btn.textContent = 'Save User';
      if (res && !res.error) {
        WG.toast('User created: ' + name, 'success');
        WG.invalidateCache('users');
        WG.closeModal('userModal');
        WG.render();
      } else {
        err.textContent = (res && res.error) || 'Create failed';
        err.style.display = 'block';
      }
    });
  }
};

WG.deleteUser = function(id) {
  WG.api('/auth/users/' + id + '/delete/', { method: 'DELETE' }).then(function(res) {
    if (res && !res.error) {
      WG.toast('User deleted: ' + (res.name || ''), 'info');
      WG.invalidateCache('users');
      WG.render();
    } else {
      WG.toast((res && res.error) || 'Delete failed', 'error');
    }
  });
};
