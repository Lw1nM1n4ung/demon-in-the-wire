/* Wire_Ghost — Global state & config */
window.WG = window.WG || {};

WG.API_BASE = '/api';

WG.state = {
  currentPage: 'dashboard',
  filters: { severity: '', source: '', search: '' },
  pagination: { page: 1, pageSize: 25, total: 0 },
};
