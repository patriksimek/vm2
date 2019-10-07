const match = (wildcard, s) => {
	const regexString = wildcard.replace(/\*/g, '\\S*').replace(/\?/g, '.');
	const regex = new RegExp(regexString);
	return regex.test(s);
};

module.exports = {match};
