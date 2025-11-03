// Appointments Calendar JavaScript
let calendar;
let currentAppointmentId = null;
let allAppointments = [];
const canManageAppointments = window.userInfo && (window.userInfo.role === 'ADMIN' || window.userInfo.role === 'PT');

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    // Load lists first
    loadPTList();
    loadClinicList();
    
    // Then initialize the calendar, which will trigger the first event load
    initializeCalendar();

    // Set minimum date to today
    const dateInput = document.getElementById('appointmentDate');
    if (dateInput) {
        dateInput.min = new Date().toISOString().split('T')[0];
    }

    // Add event listeners for filters to refetch events
    const filterPT = document.getElementById('filterPT');
    const filterClinic = document.getElementById('filterClinic');
    const filterStatus = document.getElementById('filterStatus');

    if (filterPT) filterPT.addEventListener('change', () => calendar.refetchEvents());
    if (filterClinic) filterClinic.addEventListener('change', () => calendar.refetchEvents());
    if (filterStatus) filterStatus.addEventListener('change', () => calendar.refetchEvents());

    // Listen for Enter key in patient search
    const searchInput = document.getElementById('patientSearch');
    if (searchInput) {
        searchInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                searchPatients();
            }
        });
    }
});

// Get auth token from cookie
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

// Show alert message
function showAlert(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed top-0 start-50 translate-middle-x mt-3`;
    alertDiv.style.zIndex = '9999';
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    document.body.appendChild(alertDiv);

    setTimeout(() => {
        alertDiv.remove();
    }, 5000);
}

function normalizeDate(value) {
    if (!value) return '';
    return moment(value).format('YYYY-MM-DD');
}

function parseTime(value) {
    if (!value) return null;
    const parsed = moment(value, ['HH:mm:ss', 'HH:mm', moment.ISO_8601], true);
    return parsed.isValid() ? parsed : moment(value);
}

function normalizeTime(value) {
    const parsed = parseTime(value);
    return parsed ? parsed.format('HH:mm:ss') : '';
}

function formatTimeForInput(value) {
    const parsed = parseTime(value);
    return parsed ? parsed.format('HH:mm') : '';
}

function buildDateTime(date, time) {
    if (!date || !time) return '';
    const dt = moment(`${date} ${time}`, ['YYYY-MM-DD HH:mm:ss', 'YYYY-MM-DD HH:mm', moment.ISO_8601], true);
    return (dt.isValid() ? dt : moment(`${date}T${time}`)).format('YYYY-MM-DDTHH:mm:ss');
}

function formatStatusLabel(status) {
    if (!status) return '';
    return status
        .toString()
        .split('_')
        .map(word => word.charAt(0) + word.slice(1).toLowerCase())
        .join(' ');
}

// Initialize FullCalendar
function initializeCalendar() {
    const calendarEl = document.getElementById('calendar');

    calendar = new FullCalendar.Calendar(calendarEl, {
        initialView: 'timeGridWeek',
        headerToolbar: {
            left: 'prev,next today',
            center: 'title',
            right: 'dayGridMonth,timeGridWeek,timeGridDay,listWeek'
        },
        slotMinTime: '08:00:00',
        slotMaxTime: '20:00:00',
        slotDuration: '00:30:00',
        height: 'auto',
        expandRows: true,
        nowIndicator: true,
        editable: false,
        selectable: !!canManageAppointments,
        selectMirror: !!canManageAppointments,
        dayMaxEvents: true,

        // Click on empty slot to create appointment
        select: function(info) {
            if (!canManageAppointments) {
                return;
            }
            showBookingModal();
            document.getElementById('appointmentDate').value = moment(info.start).format('YYYY-MM-DD');
            document.getElementById('appointmentStartTime').value = moment(info.start).format('HH:mm');
            document.getElementById('appointmentEndTime').value = moment(info.end).format('HH:mm');
        },

        // Click on event to view details
        eventClick: function(info) {
            viewAppointmentDetails(info.event.id);
        },

        // Use the 'events' property as a function (JSON feed)
        // This tells FullCalendar to call this function whenever it needs events
        // (on load, on view change, or when calendar.refetchEvents() is called)
        events: loadAppointments
    });

    calendar.render();
}

// Load PT list
async function loadPTList() {
    try {
        const token = getCookie('authToken');
        const response = await fetch('/api/users?role=PT', {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) throw new Error('Failed to load PTs');

        const pts = await response.json();

        // Populate PT dropdowns
        const ptSelects = [document.getElementById('appointmentPT'), document.getElementById('filterPT')];
        ptSelects.forEach(select => {
            if (!select) return;
            const isFilter = select.id === 'filterPT';

            pts.forEach(pt => {
                const option = document.createElement('option');
                option.value = pt.id;
                option.textContent = `${pt.first_name} ${pt.last_name}`;
                select.appendChild(option);
            });
        });
    } catch (error) {
        console.error('Load PTs error:', error);
        showAlert('Failed to load PT list', 'danger');
    }
}

// Load Clinic list
async function loadClinicList() {
    try {
        const token = getCookie('authToken');
        const response = await fetch('/api/clinics', {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) throw new Error('Failed to load clinics');

        const clinics = await response.json();

        // Populate clinic dropdowns
        const clinicSelects = [document.getElementById('appointmentClinic'), document.getElementById('filterClinic')];
        clinicSelects.forEach(select => {
            if (!select) return;

            clinics.forEach(clinic => {
                const option = document.createElement('option');
                option.value = clinic.id;
                option.textContent = clinic.name;
                select.appendChild(option);
            });
        });
    } catch (error) {
        console.error('Load clinics error:', error);
        showAlert('Failed to load clinic list', 'danger');
    }
}

// Load appointments (FullCalendar JSON Feed)
async function loadAppointments(fetchInfo, successCallback, failureCallback) {
    try {
        const token = getCookie('authToken');
        // console.log('Loading appointments for range:', fetchInfo.start, fetchInfo.end); // DEBUG

        // Build query parameters
        const params = new URLSearchParams();

        // Get filters
        const ptFilter = document.getElementById('filterPT').value;
        const clinicFilter = document.getElementById('filterClinic').value;
        const statusFilter = document.getElementById('filterStatus').value;

        if (ptFilter) params.append('pt_id', ptFilter);
        if (clinicFilter) params.append('clinic_id', clinicFilter);
        if (statusFilter) params.append('status', statusFilter);

        // Get date range from FullCalendar's fetchInfo
        if (fetchInfo) {
            params.append('start_date', moment(fetchInfo.start).format('YYYY-MM-DD'));
            
            // FIX: FullCalendar's `end` date is exclusive. 
            // We subtract 1 day to get the *inclusive* end date for the API query.
            const endDate = moment(fetchInfo.end).subtract(1, 'day').format('YYYY-MM-DD');
            params.append('end_date', endDate);
            // console.log('Fetching with params:', params.toString()); // DEBUG
        }

        const response = await fetch(`/api/appointments?${params.toString()}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
             // console.error('Failed to load appointments, status:', response.status); // DEBUG
             throw new Error('Failed to load appointments');
        }

        const rawAppointments = await response.json();
        allAppointments = rawAppointments.map(apt => {
            const appointmentDate = normalizeDate(apt.appointment_date);
            const startTime = normalizeTime(apt.start_time);
            const endTime = normalizeTime(apt.end_time);
            const startDateTime = buildDateTime(appointmentDate, startTime);
            const endDateTime = buildDateTime(appointmentDate, endTime);
            const fallbackName = [apt.first_name, apt.last_name].filter(Boolean).join(' ').trim();
            const patientName = (apt.patient_name || fallbackName || 'Unknown patient').trim();
            const ptName = (apt.pt_name || 'Unassigned PT').trim();

            return {
                ...apt,
                appointment_date: appointmentDate,
                start_time: startTime,
                end_time: endTime,
                start_datetime: startDateTime,
                end_datetime: endDateTime,
                patient_name: patientName,
                pt_name: ptName,
                clinic_name: apt.clinic_name || 'Unknown clinic',
                created_by_name: apt.created_by_name || '',
                cancelled_by_name: apt.cancelled_by_name || ''
            };
        });
        // console.log('Appointments loaded:', allAppointments); // DEBUG

        // Calculate quick stats
        calculateQuickStats(allAppointments);
        renderUpcomingAppointments(allAppointments);

        // Convert to FullCalendar events
        const events = allAppointments.map(apt => ({
            id: apt.id,
            title: `${apt.patient_name} • ${apt.pt_name}`,
            start: apt.start_datetime,
            end: apt.end_datetime,
            backgroundColor: getStatusColor(apt.status),
            borderColor: getStatusColor(apt.status),
            classNames: [`appointment-status-${apt.status}`],
            extendedProps: {
                appointment: apt
            }
        }));

        // Pass the formatted events to FullCalendar
        successCallback(events);

    } catch (error) {
        console.error('Load appointments error:', error);
        showAlert('Failed to load appointments', 'danger');
        // Tell FullCalendar about the failure
        if (failureCallback) failureCallback(error);
    }
}

// Get color for appointment status
function getStatusColor(status) {
    const colors = {
        'SCHEDULED': '#0d6efd',
        'COMPLETED': '#198754',
        'CANCELLED': '#6c757d',
        'NO_SHOW': '#dc3545'
    };
    return colors[status] || '#6c757d';
}

// Show booking modal
function showBookingModal() {
    if (!canManageAppointments) {
        showAlert('You do not have permission to create appointments.', 'warning');
        return;
    }
    const modalEl = document.getElementById('bookingModal');
    const form = document.getElementById('appointmentForm');

    if (!modalEl || !form) {
        console.error('Booking modal elements are missing from the page.');
        return;
    }
    currentAppointmentId = null;
    form.reset();
    document.getElementById('modalTitle').textContent = 'New Appointment';
    document.getElementById('selectedPatientInfo').style.display = 'none';
    document.getElementById('patientSearchResults').style.display = 'none';
    document.getElementById('conflictWarning').style.display = 'none';

    const modal = new bootstrap.Modal(modalEl);
    modal.show();
}

// Search patients
async function searchPatients() {
    const searchTerm = document.getElementById('patientSearch').value.trim();

    if (searchTerm.length < 2) {
        showAlert('Please enter at least 2 characters to search', 'warning');
        return;
    }

    try {
        const token = getCookie('authToken');
        const response = await fetch(`/api/patients/search?q=${encodeURIComponent(searchTerm)}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) throw new Error('Search failed');

        const patients = await response.json();

        const resultsDiv = document.getElementById('patientSearchResults');
        resultsDiv.innerHTML = '';

        if (patients.length === 0) {
            resultsDiv.innerHTML = '<div class="p-3 text-muted">No patients found</div>';
        } else {
            patients.forEach(patient => {
                const div = document.createElement('div');
                div.className = 'patient-search-result';
                div.innerHTML = `
                    <strong>${patient.first_name} ${patient.last_name}</strong><br>
                    <small>HN: ${patient.hn} | PT: ${patient.pt_number || 'N/A'} | DOB: ${moment(patient.dob).format('DD/MM/YYYY')}</small>
                `;
                div.onclick = () => selectPatient(patient);
                resultsDiv.appendChild(div);
            });
        }

        resultsDiv.style.display = 'block';

    } catch (error) {
        console.error('Search patients error:', error);
        showAlert('Failed to search patients', 'danger');
    }
}

// Select patient from search results
function selectPatient(patient) {
    document.getElementById('selectedPatientId').value = patient.id;
    document.getElementById('selectedPatientDisplay').textContent =
        `${patient.first_name} ${patient.last_name} (HN: ${patient.hn})`;
    document.getElementById('selectedPatientInfo').style.display = 'block';
    document.getElementById('patientSearchResults').style.display = 'none';
    document.getElementById('patientSearch').value = '';
}

// Set duration (quick select buttons)
function setDuration(minutes) {
    const startTime = document.getElementById('appointmentStartTime').value;

    if (!startTime) {
        showAlert('Please select start time first', 'warning');
        return;
    }

    const [hours, mins] = startTime.split(':').map(Number);
    const startDate = new Date();
    startDate.setHours(hours, mins, 0);

    const endDate = new Date(startDate.getTime() + minutes * 60000);
    const endTime = `${String(endDate.getHours()).padStart(2, '0')}:${String(endDate.getMinutes()).padStart(2, '0')}`;

    document.getElementById('appointmentEndTime').value = endTime;
    checkConflicts();
}

// Check for time conflicts
async function checkConflicts() {
    const ptId = document.getElementById('appointmentPT').value;
    const date = document.getElementById('appointmentDate').value;
    const startTime = document.getElementById('appointmentStartTime').value;
    const endTime = document.getElementById('appointmentEndTime').value;

    if (!ptId || !date || !startTime || !endTime) {
        return; // Not enough info to check
    }

    try {
        const token = getCookie('authToken');
        const response = await fetch('/api/appointments/check-conflict', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                pt_id: ptId,
                appointment_date: date,
                start_time: startTime,
                end_time: endTime,
                exclude_appointment_id: currentAppointmentId
            })
        });

        if (!response.ok) throw new Error('Conflict check failed');

        const result = await response.json();

        const warningDiv = document.getElementById('conflictWarning');
        if (result.hasConflict) {
            const conflictList = result.conflicts.map(c =>
                `${c.patient_name} (${c.start_time} - ${c.end_time})`
            ).join(', ');

            document.getElementById('conflictMessage').textContent =
                `This time slot conflicts with: ${conflictList}`;
            warningDiv.style.display = 'block';
        } else {
            warningDiv.style.display = 'none';
        }

    } catch (error) {
        console.error('Check conflict error:', error);
    }
}

// Save appointment
async function saveAppointment() {
    if (!canManageAppointments) {
        showAlert('You do not have permission to modify appointments.', 'warning');
        return;
    }
    const patientId = document.getElementById('selectedPatientId').value;
    const ptId = document.getElementById('appointmentPT').value;
    const clinicId = document.getElementById('appointmentClinic').value;
    const date = document.getElementById('appointmentDate').value;
    const startTime = document.getElementById('appointmentStartTime').value;
    const endTime = document.getElementById('appointmentEndTime').value;

    // Validation
    if (!patientId) {
        showAlert('Please select a patient', 'warning');
        return;
    }
    if (!ptId || !clinicId || !date || !startTime || !endTime) {
        showAlert('Please fill in all required fields', 'warning');
        return;
    }

    // Check if there's a conflict warning
    if (document.getElementById('conflictWarning').style.display !== 'none') {
        if (!confirm('There is a time conflict. Do you want to proceed anyway?')) {
            return;
        }
    }

    const appointmentData = {
        patient_id: patientId,
        pt_id: ptId,
        clinic_id: clinicId,
        appointment_date: date,
        start_time: startTime,
        end_time: endTime,
        appointment_type: document.getElementById('appointmentType').value,
        reason: document.getElementById('appointmentReason').value,
        notes: document.getElementById('appointmentNotes').value
    };

    try {
        const token = getCookie('authToken');
        const url = currentAppointmentId
            ? `/api/appointments/${currentAppointmentId}`
            : '/api/appointments';
        const method = currentAppointmentId ? 'PUT' : 'POST';

        const response = await fetch(url, {
            method: method,
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(appointmentData)
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to save appointment');
        }

        showAlert(`Appointment ${currentAppointmentId ? 'updated' : 'created'} successfully!`, 'success');

        // Close modal and refetch events
        const modalEl = document.getElementById('bookingModal');
        const modalInstance = modalEl ? bootstrap.Modal.getInstance(modalEl) : null;
        if (modalInstance) {
            modalInstance.hide();
        }
        // This will trigger the 'events' function in FullCalendar
        calendar.refetchEvents();

    } catch (error) {
        console.error('Save appointment error:', error);
        showAlert(error.message, 'danger');
    }
}

// View appointment details
async function viewAppointmentDetails(appointmentId) {
    const appointment = allAppointments.find(a => a.id == appointmentId);

    // FIX: Add check and alert if appointment is not found
    if (!appointment) {
        showAlert('Appointment not found or data is still loading.', 'danger');
        console.error('Could not find appointment with ID:', appointmentId, 'in', allAppointments);
        return;
    }

    currentAppointmentId = appointmentId;

    const statusLabel = formatStatusLabel(appointment.status);
    const startMoment = moment(appointment.start_datetime || `${appointment.appointment_date}T${appointment.start_time}`);
    const endMoment = moment(appointment.end_datetime || `${appointment.appointment_date}T${appointment.end_time}`);
    const createdMoment = appointment.created_at ? moment(appointment.created_at) : null;
    const updatedMoment = appointment.updated_at ? moment(appointment.updated_at) : null;
    const cancelledMoment = appointment.cancelled_at ? moment(appointment.cancelled_at) : null;

    const detailsHtml = `
        <div class="row">
            <div class="col-md-6">
                <p><strong>Patient:</strong> ${appointment.patient_name}</p>
                <p><strong>HN:</strong> ${appointment.hn}</p>
                <p><strong>PT Number:</strong> ${appointment.pt_number || 'N/A'}</p>
            </div>
            <div class="col-md-6">
                <p><strong>PT:</strong> ${appointment.pt_name}</p>
                <p><strong>Clinic:</strong> ${appointment.clinic_name}</p>
                <p><strong>Status:</strong> <span class="badge bg-${getStatusBadge(appointment.status)}">${statusLabel}</span></p>
            </div>
        </div>
        <hr>
        <div class="row">
            <div class="col-md-12">
                <p><strong>Date:</strong> ${moment(appointment.appointment_date).format('dddd, MMMM DD, YYYY')}</p>
                <p><strong>Time:</strong> ${startMoment.format('HH:mm')} - ${endMoment.format('HH:mm')}</p>
                ${appointment.appointment_type ? `<p><strong>Type:</strong> ${appointment.appointment_type}</p>` : ''}
                ${appointment.reason ? `<p><strong>Reason:</strong> ${appointment.reason}</p>` : ''}
                ${appointment.notes ? `<p><strong>Notes:</strong> ${appointment.notes}</p>` : ''}
                ${appointment.created_by_name ? `<p><strong>Created by:</strong> ${appointment.created_by_name}</p>` : ''}
                ${createdMoment ? `<p><strong>Created at:</strong> ${createdMoment.format('DD MMM YYYY HH:mm')}</p>` : ''}
                ${updatedMoment ? `<p><strong>Last updated:</strong> ${updatedMoment.format('DD MMM YYYY HH:mm')}</p>` : ''}
            </div>
        </div>
        ${appointment.cancellation_reason ? `
            <hr>
            <div class="alert alert-warning">
                <strong>Cancellation Reason:</strong> ${appointment.cancellation_reason}<br>
                ${appointment.cancelled_by_name ? `<span>Cancelled by: ${appointment.cancelled_by_name}</span><br>` : ''}
                ${cancelledMoment ? `<span>Cancelled at: ${cancelledMoment.format('DD MMM YYYY HH:mm')}</span>` : ''}
            </div>
        ` : ''}
    `;

    document.getElementById('appointmentDetails').innerHTML = detailsHtml;

    const modal = new bootstrap.Modal(document.getElementById('viewAppointmentModal'));
    modal.show();
}

// Get badge class for status
function getStatusBadge(status) {
    const badges = {
        'SCHEDULED': 'primary',
        'COMPLETED': 'success',
        'CANCELLED': 'secondary',
        'NO_SHOW': 'danger'
    };
    return badges[status] || 'secondary';
}

// Reschedule appointment
function rescheduleAppointment() {
    if (!canManageAppointments) {
        showAlert('You do not have permission to reschedule appointments.', 'warning');
        return;
    }
    const appointment = allAppointments.find(a => a.id == currentAppointmentId);

    if (!appointment) return;

    // Close view modal
    bootstrap.Modal.getInstance(document.getElementById('viewAppointmentModal')).hide();

    // Open booking modal with data
    showBookingModal();
    document.getElementById('modalTitle').textContent = 'Reschedule Appointment';

    // Fill form
    document.getElementById('selectedPatientId').value = appointment.patient_id;
    document.getElementById('selectedPatientDisplay').textContent =
        `${appointment.patient_name} (HN: ${appointment.hn})`;
    document.getElementById('selectedPatientInfo').style.display = 'block';

    document.getElementById('appointmentPT').value = appointment.pt_id;
    document.getElementById('appointmentClinic').value = appointment.clinic_id;
    document.getElementById('appointmentDate').value = appointment.appointment_date;
    document.getElementById('appointmentStartTime').value = formatTimeForInput(appointment.start_time);
    document.getElementById('appointmentEndTime').value = formatTimeForInput(appointment.end_time);
    document.getElementById('appointmentType').value = appointment.appointment_type || '';
    document.getElementById('appointmentReason').value = appointment.reason || '';
    document.getElementById('appointmentNotes').value = appointment.notes || '';
}

// Mark appointment as completed
async function markAsCompleted() { // <-- SYNTAX ERROR FIX: Removed the extra '.'
    if (!canManageAppointments) {
        showAlert('You do not have permission to update appointments.', 'warning');
        return;
    }
    if (!confirm('Mark this appointment as completed?')) return;

    try {
        const token = getCookie('authToken');
        const response = await fetch(`/api/appointments/${currentAppointmentId}`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ status: 'COMPLETED' })
        });

        if (!response.ok) throw new Error('Failed to update status');

        showAlert('Appointment marked as completed', 'success');
        bootstrap.Modal.getInstance(document.getElementById('viewAppointmentModal')).hide();
        // Refetch events
        calendar.refetchEvents();

    } catch (error) {
        console.error('Mark completed error:', error);
        showAlert('Failed to update appointment status', 'danger');
    }
}

// Cancel appointment
async function cancelAppointment() {
    if (!canManageAppointments) {
        showAlert('You do not have permission to cancel appointments.', 'warning');
        return;
    }
    const reason = prompt('Please enter cancellation reason:');

    if (reason === null) return; // User cancelled

    try {
        const token = getCookie('authToken');
        const response = await fetch(`/api/appointments/${currentAppointmentId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ cancellation_reason: reason })
        });

        if (!response.ok) throw new Error('Failed to cancel appointment');

        showAlert('Appointment cancelled successfully', 'success');
        bootstrap.Modal.getInstance(document.getElementById('viewAppointmentModal')).hide();
        // Refetch events
        calendar.refetchEvents();

    } catch (error) {
        console.error('Cancel appointment error:', error);
        showAlert('Failed to cancel appointment', 'danger');
    }
}

// Calculate quick stats (today, week, month)
function calculateQuickStats(appointments) {
    const now = moment();
    const todayStart = moment().startOf('day');
    const todayEnd = moment().endOf('day');
    const weekStart = moment().startOf('week');
    const weekEnd = moment().endOf('week');
    const monthStart = moment().startOf('month');
    const monthEnd = moment().endOf('month');

    let todayCount = 0;
    let weekCount = 0;
    let monthCount = 0;

    // Filter out CANCELLED appointments from stats
    const activeAppointments = appointments.filter(apt => apt.status !== 'CANCELLED');

    activeAppointments.forEach(apt => {
        const aptDate = moment(apt.appointment_date);

        if (aptDate.isBetween(todayStart, todayEnd, null, '[]')) {
            todayCount++;
        }
        if (aptDate.isBetween(weekStart, weekEnd, null, '[]')) {
            weekCount++;
        }
        if (aptDate.isBetween(monthStart, monthEnd, null, '[]')) {
            monthCount++;
        }
    });

    // Update UI
    document.getElementById('todayCount').textContent = todayCount;
    document.getElementById('weekCount').textContent = weekCount;
    document.getElementById('monthCount').textContent = monthCount;
}

function renderUpcomingAppointments(appointments) {
    const list = document.getElementById('upcomingAppointments');
    const emptyState = document.getElementById('upcomingEmptyState');
    const countBadge = document.getElementById('upcomingCount');

    if (!list || !emptyState || !countBadge) {
        return;
    }

    list.innerHTML = '';

    const now = moment();
    const horizon = moment().add(14, 'days').endOf('day');

    const upcoming = appointments
        .filter(apt => apt.status !== 'CANCELLED')
        .map(apt => {
            const startMoment = moment(apt.start_datetime || `${apt.appointment_date}T${apt.start_time}`);
            const endMoment = moment(apt.end_datetime || `${apt.appointment_date}T${apt.end_time}`);
            return { ...apt, startMoment, endMoment };
        })
        .filter(apt => apt.startMoment.isValid() && apt.startMoment.isSameOrAfter(now, 'minute'))
        .filter(apt => apt.startMoment.isSameOrBefore(horizon, 'minute'))
        .sort((a, b) => a.startMoment.valueOf() - b.startMoment.valueOf());

    countBadge.textContent = upcoming.length;

    if (upcoming.length === 0) {
        emptyState.style.display = 'block';
        return;
    }

    emptyState.style.display = 'none';

    upcoming.slice(0, 5).forEach(apt => {
        const item = document.createElement('li');
        item.className = 'list-group-item p-3';
        item.innerHTML = `
            <div class="d-flex justify-content-between align-items-start gap-3">
                <div>
                    <div class="fw-semibold">${apt.patient_name}</div>
                    <div class="text-muted small">${apt.startMoment.format('ddd, DD MMM YYYY')} · ${apt.startMoment.format('HH:mm')} - ${apt.endMoment.format('HH:mm')}</div>
                    <div class="text-muted small">
                        <i class="bi bi-person-badge me-1"></i>${apt.pt_name}
                        <span class="mx-1">•</span>
                        <i class="bi bi-building me-1"></i>${apt.clinic_name}
                    </div>
                </div>
                <span class="badge rounded-pill bg-${getStatusBadge(apt.status)}">${formatStatusLabel(apt.status)}</span>
            </div>
        `;
        item.addEventListener('click', () => viewAppointmentDetails(apt.id));
        list.appendChild(item);
    });
}

