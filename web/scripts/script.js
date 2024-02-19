document.addEventListener('DOMContentLoaded', function() {
	initializeDarkMode();
	loadConfigs();
	loadLogs();
	document.getElementById('darkModeToggle').addEventListener('click', function() {
		toggleDarkMode();
	});	
});

function loadConfigs() {
	fetch('/api/configs')
		.then(response => response.json())
		.then(data => {
			const configsTableBody = document.getElementById('configsTableBody');
			configsTableBody.innerHTML = ''; 
			data.forEach(config => {
				let row = configsTableBody.insertRow();
				row.insertCell(0).innerText = config.ID;
				row.insertCell(1).innerText = config.Name;
				row.insertCell(2).innerText = config.CVE;
				row.insertCell(3).innerText = config.Application;
				row.insertCell(4).innerText = config.Port;
				row.insertCell(5).innerText = config.TemplateHTMLFile;
				row.insertCell(6).innerText = config.DetectionEndpoint;
				row.insertCell(7).innerText = config.RequestRegex;
				row.insertCell(8).innerText = config.DateCreated;
				row.insertCell(9).innerText = config.DateUpdated;
				row.insertCell(10).innerText = config.RedirectURL;
				let enabledCell = row.insertCell(11);
				enabledCell.innerText = config.Enabled ? 'Yes' : 'No';

				let actionsCell = row.insertCell(12);
				let editButton = document.createElement('button');
				editButton.innerText = 'Edit';
				editButton.className = 'btn btn-sm btn-secondary';
				editButton.onclick = () => showConfigForm(config);
				actionsCell.appendChild(editButton);

				let toggleButton = document.createElement('button');
				toggleButton.innerText = config.Enabled ? 'Disable' : 'Enable';
				toggleButton.className = 'btn btn-sm btn-warning';
				toggleButton.onclick = () => toggleConfig(config.ID, !config.Enabled);
				actionsCell.appendChild(toggleButton);

				let removeButton = document.createElement('button');
				removeButton.classList.add('btn', 'btn-danger', 'btn-sm');
				removeButton.textContent = 'Remove';
				removeButton.onclick = () => removeConfig(config.ID);
				actionsCell.appendChild(removeButton);
			});
		})
		.catch(error => console.error('Unable to load configurations:', error));
}

function initializeDarkMode() {
    if (localStorage.getItem('darkMode') === 'enabled') {
        document.body.classList.add('dark-mode');
    } else {
        document.body.classList.remove('dark-mode');
    }
}

function toggleDarkMode() {
    if (document.body.classList.contains('dark-mode')) {
        document.body.classList.remove('dark-mode');
        localStorage.setItem('darkMode', 'disabled');
    } else {
        document.body.classList.add('dark-mode');
        localStorage.setItem('darkMode', 'enabled');
    }
}

function loadLogs() {
	fetch('/api/logs')
		.then(response => response.json())
		.then(data => {
			const logsTableBody = document.getElementById('logsTableBody');
			logsTableBody.innerHTML = '';
			data.forEach(log => {
				let row = logsTableBody.insertRow();
				row.insertCell(0).innerText = log.ID;
				row.insertCell(1).innerText = log.Datetime;
				row.insertCell(2).innerText = log.IPSource;
				row.insertCell(3).innerText = log.IPDestination;
				let eventCell = row.insertCell(4);
				eventCell.innerText = log.LogEvent;
				eventCell.classList.add('event-column');
				let regexMatchCell = row.insertCell(5);
				regexMatchCell.innerText = log.regex_match === 'no' ? 'No' : 'Yes';
			});
			adjustEventColumnStyling();
		})
		.catch(error => console.error('Unable to load logs:', error));
}

function adjustEventColumnStyling() {
	document.querySelectorAll('#logsTable tbody tr').forEach(row => {
		const eventCell = row.cells[4];
		if (eventCell) {
			eventCell.classList.add('event-column');
		}
	});
}

function showConfigForm(config = null) {
	const form = document.getElementById('configForm');
	form.reset(); 

	if (config) {
		document.getElementById('configName').value = config.Name;
		document.getElementById('configCVE').value = config.CVE;
		document.getElementById('configApplication').value = config.Application;
		document.getElementById('configPort').value = config.Port;
		document.getElementById('configTemplateHTMLFile').value = config.TemplateHTMLFile;
		document.getElementById('configDetectionEndpoint').value = config.DetectionEndpoint;
		document.getElementById('configRequestRegex').value = config.RequestRegex;
		document.getElementById('configDateCreated').value = config.DateCreated;
		document.getElementById('configDateUpdated').value = config.DateUpdated;
		document.getElementById('configRedirectURL').value = config.RedirectURL;
		document.getElementById('configEnabled').checked = config.Enabled;
		form.dataset.configId = config.ID; 
	} else {
		delete form.dataset.configId; 
	}

	$('#configModal').modal('show');
}

function submitConfigForm() {
	const form = document.getElementById('configForm');
	const configId = form.dataset.configId;
	const formData = {
		Name: form.configName.value,
		CVE: form.configCVE.value,
		Application: form.configApplication.value,
		Port: parseInt(form.configPort.value, 10),
		TemplateHTMLFile: form.configTemplateHTMLFile.value,
		DetectionEndpoint: form.configDetectionEndpoint.value,
		RequestRegex: form.configRequestRegex.value,
		DateCreated: form.configDateCreated.value,
		DateUpdated: form.configDateUpdated.value,
		RedirectURL: form.configRedirectURL.value,
		Enabled: form.configEnabled.checked
	};

	let url = '/api/configs' + (configId ? `/${configId}` : '');
	let method = configId ? 'PUT' : 'POST';

	fetch(url, {
		method: method,
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify(formData),
	})
	.then(response => {
		if (!response.ok) {
			throw new Error('Network response was not ok');
		}
		return response.json();
	})
	.then(() => {
		$('#configModal').modal('hide');
		loadConfigs();
	})
	.catch(error => {
		console.error('Error:', error);
	});
}

function toggleConfig(configId, enabled) {
	enableDisableHoneypot(configId, enabled);
}

function enableDisableHoneypot(configId, enabled) {
	fetch(`/api/configs/${configId}/enable-disable`, {
		method: 'PUT',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({ enabled: enabled }),
	})
	.then(response => {
		if (!response.ok) {
			throw new Error('Network response was not ok');
		}
		return response.json();
	})
	.then(() => {
		console.log(`Config ${configId} enabled/disabled to ${enabled}`);
		loadConfigs();
	})
	.catch(error => {
		console.error('Error enabling/disabling configuration:', error);
	});
}

function removeConfig(configId) {
	if(confirm(`Are you sure you want to remove the configuration with ID ${configId}?`)) {
		fetch(`/api/configs/${configId}`, {
			method: 'DELETE',
		})
		.then(response => {
			if(response.ok) {
				loadConfigs();
				alert('Configuration removed successfully.');
			} else {
				alert('Failed to remove configuration.');
			}
		})
		.catch(error => console.error('Error removing configuration:', error));
	}
}
