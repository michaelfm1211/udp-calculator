///
// validation
///

// Validation function factory
function validate(cond, msg) {
	return function(e) {
		const errSpan = e.target.parentNode.querySelector('.validation');
		if (!cond(e.target.value)) {
			errSpan.textContent = msg;
		} else if (errSpan.textContent === msg) {
			errSpan.textContent = '';
		}
	}
}

// Valid hex value
const validHex = validate(str => /^[0-9a-fA-F\s]*$/.test(str),
	'Value is not a valid hexadecimal value.');
document.querySelector('#ip_id').addEventListener('change', validHex);
document.querySelector('#ip_ttl').addEventListener('change', validHex);

const validDec = validate(str => /^[0-9]*$/.test(str),
	'Value is not a valid decimal value.');
document.querySelector('#udp_src').addEventListener('change', validHex);
document.querySelector('#udp_dst').addEventListener('change', validHex);

// Maximum Length
const maxlen = n => validate(str => str.replaceAll(' ', '').length <= n,
	'Value is too long.');
document.querySelector('#ip_id').addEventListener('change', maxlen(4));
document.querySelector('#ip_ttl').addEventListener('change', maxlen(2));

// Valid port
const validPort = validate(str => {
	if (str === '') return true;
	else if (!/^\d*$/.test(str)) return false;
	return parseInt(str) >= 1 && parseInt(str) <= 65535;
}, 'Value is not a valid port.');
document.querySelector('#udp_src').addEventListener('change', validPort);
document.querySelector('#udp_dst').addEventListener('change', validPort);

document.querySelector('#udp_data').addEventListener('change',
	validate(str => str.length <= 65507, 'Value is too long.'));

// Valid IPv4 address in dot notation
const validIP = validate(str => {
	if (str === '') return true;
	const nums = str.split('.');
	if (nums.length !== 4) return false;
	for (let n of nums) {
		n = parseInt(n);
		if (Number.isNaN(n) || n < 0 || n > 255) return false;
	}
	return true;
}, 'Value is not a valid IP address.');
document.querySelector('#ip_src').addEventListener('change', validIP);
document.querySelector('#ip_dst').addEventListener('change', validIP);

///
// Calculate & Show Output
///

// Returns a the Number `n` as a string of its hexadecimal value with at most
// `d` leading zeroes. Spaces are added for readability.
const asHex = (n, d) => n.toString(16).padStart(d, '0').replace(/(..)/g, '$1 ')
	.slice(0, -1);

// Parse an IPv4 address in dot notation into an array of two 16-bit words.
function parseIP(ip) {
	const nums = ip.split('.');
	return [(nums[0] << 8) | nums[1],
		(nums[2] << 8) | nums[3]];
}

// Calculate a checksum given an array of 16 bit words
function checksum(data) {
	let sum = 0;
	for (const word of data) {
		let ones = sum + word;
		if (ones >= (1 << 16)) ones = (ones + 1) % (1 << 16);
		sum = ones;
	}
	return 0xffff - sum;
}

function go() {
	// don't run if anything is invalid
	const validations = document.querySelectorAll('.validation');
	if ([...validations].some(el => el.textContent !== '')) {
		document.querySelector('#output_bin').textContent = "Error";
		return;
	}
	// 

	// get the header fields and parse them
	const ip_id = parseInt(document.querySelector('#ip_id').value, 16) || 0;
	const ip_ttl = parseInt(document.querySelector('#ip_ttl').value, 16) || 40;
	const ip_src = parseIP(document.querySelector('#ip_src').value || '127.0.0.1');
	const ip_dst = parseIP(document.querySelector('#ip_dst').value || '127.0.0.1');
	const udp_src = parseInt(document.querySelector('#udp_src').value) || 1;
	const udp_dst = parseInt(document.querySelector('#udp_dst').value) || 1;
	const udp_data = document.querySelector('#udp_data').value;

	// calculate the IP packet length
	const ip_len = udp_data.length + 28;
	document.querySelector('#ip_len').textContent = asHex(ip_len, 4);

	// calculate UDP length
	const udp_len = udp_data.length + 8;
	document.querySelector('#udp_len').textContent = asHex(udp_len, 4);

	// calculate the IP header checksum
	const ip_chkdata = [(4 << 12) | (5 << 8) | 0, ip_len, ip_id, 0,
		(ip_ttl << 8) | 0x11, 0, ...ip_src, ...ip_dst];
	const ip_chk = checksum(ip_chkdata);
	document.querySelector('#ip_chk').textContent = asHex(ip_chk, 4);

	// calculate the UDP checksum
	let udp_chkdata = [udp_src, udp_dst, udp_len, 0];
	// alignment for the checksum, later undone
	const tmp = udp_data.length % 2 === 0 ? udp_data : udp_data + '\0';
	for (let i = 0; i < udp_data.length; i += 2) {
		udp_chkdata.push((tmp.charCodeAt(i) << 8) |
			tmp.charCodeAt(i + 1));
	}
	
	let udp_chk = 0;
	if (document.querySelector('#udp_chk_enabled').checked) {
		const psuedo = [...ip_src, ...ip_dst, 0x11, udp_len, ...udp_chkdata];
		udp_chk = checksum(psuedo);
		document.querySelector('#udp_chk').textContent = asHex(udp_chk, 4);
	} else {
		document.querySelector('#udp_chk').textContent = '00 00';
	}

	// output everything to the output bin
	ip_chkdata[5] = ip_chk;
	udp_chkdata[3] = udp_chk;
	let out = ip_chkdata.map(n => asHex(n, 4)).join(' ') + ' ';
	// remove padding used in checksum
	if (udp_data.length % 2 == 0) {
		out += udp_chkdata.map(n => asHex(n, 4)).join(' ');
	} else {
		out += udp_chkdata.slice(0, -1).map(n => asHex(n, 4)).join(' ');
		out += ' ' + asHex(udp_chkdata.at(-1), 4).slice(0, 2)
	}
	document.querySelector('#output_bin').textContent = out;
}

const inputs = document.getElementsByTagName('input');
for (const input of inputs) {
	input.addEventListener('change', go);
}
go();

document.querySelector('#output_bin').addEventListener('click', async (e) => {
	await navigator.clipboard.writeText(e.target.textContent);

	const output_msg = document.querySelector('#output_msg');
	const tmp = output_msg.textContent;
	output_msg.textContent = 'Copied!';
	setTimeout(() => output_msg.textContent = tmp, 2000);
});
