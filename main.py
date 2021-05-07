'''------<imports>------'''
import capstone as cs
import binascii as ba
import numpy as np
import r2pipe
import json
import pickle
from scipy import spatial, sparse
import time
import sklearn.preprocessing as pp
'''------</imports>------'''

'''------<settings>------'''
debug = False
arch = cs.CS_ARCH_X86 # x86 architecture
mode = cs.CS_MODE_64 # 64-bit mode
binaryPath = './stack_buffer_overflow/'
spacesPath = './spaces/'
modelPath = './models/'
'''------</settings>------'''

'''------<functions>------'''
def find_ngrams(input, n, delimeter=';'):
	output = [delimeter.join(input[i:i+n]) for i in range(len(input)-n+1)]
	return output

def getCountOfBadFuncs(r2, fname):
	with open(spacesPath+'vulnApiFuncs.txt', 'r') as f: badFuncs = f.read().splitlines()
	funcs = r2.cmd('aflmj')
	funcsj = json.loads(funcs)
	output = {}
	for i in funcsj:
		if i['name'] == fname:
			for j in i['calls']:
				tmp = j['name'].split('.')[-1]
				if debug: print(tmp)
				if tmp in badFuncs: output[tmp] = 1
	if debug: print(output)
	return output

def getMeta(r2, fname):
	jdata = json.loads(r2.cmd('pdfj @ {}'.format(fname)))
	output = []
	first = 0
	if jdata['ops']: first = jdata['ops'][0]['offset']
	for elem in jdata['ops']: output.append(elem['offset']-first)
	return output

def getLocalVars(r2, fname): # need improvement on SP-based stack frame
	addr = r2.cmd('aflt~{}[0])'.format(fname)).split()[0]
	vars = json.loads(r2.cmd('afvj @ {}'.format(addr)))
	#sp = vars['sp']
	bp = vars['bp']
	#sp_offsets = []
	bp_offsets = []
	#for i in range(len(sp)): sp_offsets.append(sp[i]['ref']['offset'])
	for i in range(len(bp)): bp_offsets.append(bp[i]['ref']['offset'])
	bp_offsets.append(0)
	if debug: print(bp_offsets)
	output = list(np.diff(bp_offsets))
	if debug: print(output)
	return output

def getVulnFunc(binaryPath, analysisLvl, pattern=''):
	r2 = r2pipe.open(binaryPath, flags=['-e', 'io.cache=true'])
	r2.cmd(analysisLvl)
	output = {}
	while 1:
		if pattern != '': funcs = r2.cmd('aflt~{}[2]'.format(pattern)).split()
		else: funcs = r2.cmd('aflt~!^name$[2]').split()
		print('[-1]\tList functions in makefile style (aflm)')
		for f in range(len(funcs)):
			print('[{}]\t{}'.format(f, funcs[f]))
		try: func = int(input('Enter the number of vulnerability function >> '))
		except Exception:
			print('Incorrect input, try again!')
			continue
		if func == -1: print(r2.cmd('aflm'))
		else: 
			if func > -1 and func < len(funcs): break
	while 1:
		print('[-1]\tPrint disassembly of function (pdf @ <func>)')
		print('[0]\tThe entire function')
		print('[1]\tRange of instructions (offsets)')
		print('[2]\tAround a specific instruction (offset)')
		try: inp = int(input('Enter the number of vulnerability extraction method >> '))
		except Exception:
			print('Incorrect input, try again!')
			continue
		output['data'] = r2.cmd('p8f @ {}'.format(funcs[func])).replace('\r\n', '')
		output['vars'] = getLocalVars(r2, funcs[func])
		output['badFuncs'] = getCountOfBadFuncs(r2, funcs[func])
		if inp == -1: print(r2.cmd('pdf @ {}'.format(funcs[func])))
		elif inp == 0: break
		elif inp == 1:
			while 1:
				try:
					offsetFrom = int(input('Enter the offset FROM (hex format, e.g. 0x1337 or just 1337) >> '), 16)
					offsetTo = int(input('Enter the offset TO (hex format, e.g. 0x1337 or just 1337) >> '), 16)
				except Exception:
					print('Incorrect input, try again!')
					continue
				output['data'] = r2.cmd('p8 {} @ {}'.format(offsetTo - offsetFrom, offsetFrom)).replace('\r\n', '')
				break
			break
		elif inp == 2:
			while 1:
				try:
					offset = int(input('Enter the instruction offset (hex format, e.g. 0x1337 or just 1337) >> '), 16)
					wSize = int(input('Enter the window size of instructions (to backward use negative value) >> '))
				except Exception:
					print('Incorrect input, try again!')
					continue
				if wSize < 0:
					offset = int(r2.cmd('pdi {} @ {}~[0]:0'.format(wSize, offset)).replace('\r\n', ''), 16)
					wSize = wSize * -1
				instructionOffset = int(r2.cmd('pdi {} @ {}~[0]:-1'.format(wSize+2, offset)).replace('\r\n', ''), 16)
				a = instructionOffset - offset
				b = offset
				output['data'] = r2.cmd('p8 {} @ {}'.format(a, b)).replace('\r\n', '')
				break
			break
	r2.quit()
	if debug: print(output)
	return output

def getAllFuncs(binaryPath, analysisLvl, pattern=''):
	r2 = r2pipe.open(binaryPath, flags=['-e', 'io.cache=true'])
	r2.cmd(analysisLvl)
	if pattern != '': funcs = r2.cmd('aflt~{}[2]'.format(pattern)).split()
	else: funcs = r2.cmd('aflt~!^name$[2]').split()
	output = {}
	for f in funcs:
		output[f] = {'data': r2.cmd('p8f @ {}'.format(f)).replace('\r\n', '')}
		output[f]['meta'] = getMeta(r2, f) # [1,2,2,5,...] len = count of instructions, value = size
		output[f]['badFuncs'] = getCountOfBadFuncs(r2, f)
		output[f]['vars'] = getLocalVars(r2, f)
	r2.quit()
	if debug: print(output)
	return output

def getPseudoIntructionsNgram(data, n):
	code = ba.unhexlify(data)
	md = cs.Cs(arch, mode)
	md.detail = True
	output = {'instr':{}, 'reg':{}, 'instr_count':0, 'reg_count':0, 'call':0, 'mem':0, 'imm': 0}
	instructions = []
	regs = []
	if debug: print('-'*100+'\n'+'{}\t{}\t{}\t{}\t{}\t{:15}\t{:15}'.format('offset', 'size', 'mnem', 'rex', 'opcode', 'bytes', 'op_str')+'\n'+'-'*100)
	for i in md.disasm(code, 0x0): print('{}\t{}\t{}\t{}\t{}\t{:15}\t{:15}'.format(hex(i.address), i.size, i.mnemonic, hex(i.rex)[2:], ''.join([hex(i)[2:] if i != 0 else '' for i in i.opcode]), ba.hexlify(i.bytes).decode('ascii'), i.op_str)) if debug else print('', end='')
	for i in md.disasm(code, 0x0):
		tmp = ''
		tmp += i.mnemonic.split(' ')[-1] # cut i.prefix
		if tmp == 'call': output['call'] += 1
		if len(i.operands) > 0:
			for o in i.operands:
				if o.type == cs.x86.X86_OP_REG:
					tmp+=',reg'
					regs.append(i.reg_name(o.reg))
				if o.type == cs.x86.X86_OP_IMM:
					tmp+=',imm'
					output['imm'] += 1
				if o.type == cs.x86.X86_OP_MEM:
					tmp+=',mem'
					output['mem'] += 1
		instructions.append(tmp)
	if debug: print(instructions)
	bigrams_i = find_ngrams(instructions, n)
	bigrams_r = find_ngrams(regs, n)
	if debug: print(bigrams_i)
	if debug: print(bigrams_r)
	for i in bigrams_i:
		output['instr_count'] += 1
		if i not in output['instr']: output['instr'].update({i: 1})
		else: output['instr'][i] += 1
	for i in bigrams_r:
		output['reg_count'] += 1
		if i not in output['reg']: output['reg'].update({i: 1})
		else: output['reg'][i] += 1
	if debug: print(output)
	return output # output format: {instr: {}, reg: {}, instr_count: N, reg_count: N, call: N, mem: N, imm: N}

def getVectorByCounter(data, space, sample=''):
	with open(space, 'r') as f: vectorSpace = f.read().splitlines()
	vector = []
	for elem in vectorSpace:
		if elem in data: vector.append(data[elem])
		else: vector.append(0)
	return vector

def getVectorByTfIdf(data, count, term_space, idf_space, sample=''):
	with open(term_space, 'r') as f: vectorSpace = f.read().splitlines()
	with open(idf_space, 'r') as f: idf = f.read().splitlines()
	vector = []
	for item in data: data[item] /= count # tf
	for i in range(len(vectorSpace)):
		if vectorSpace[i] in data: vector.append(data[vectorSpace[i]] * float(idf[i]))
		else: vector.append(0)
	return vector

def getSparseVector(data, length):
	tmp = {}
	for i in data:
		if i not in tmp: tmp[i] = 1
		else: tmp[i] += 1
	sv = {}
	sv['data'] = tmp
	sv['len'] = length
	return sv

def fast_cosine_similarities(mat):
	col_normed_mat = pp.normalize(mat.T, axis=0)
	return (col_normed_mat.T * col_normed_mat).toarray()[0][1]

def normalize(v, n):
	norm = np.linalg.norm(v, ord=n)
	if norm == 0: return v
	return v / norm

def compareVectors(vector1, vector2):
	vector = sparse.vstack([vector1, vector2])
	vec1, vec2 = vector[0].toarray(), vector[1].toarray()
	euc_dis = spatial.distance.euclidean(vec1, vec2) # ** 2
	euc_dis_normL1 = spatial.distance.euclidean(normalize(vec1, 1), normalize(vec2, 1)) # ** 2
	if vector[0].count_nonzero() == 0 or vector[1].count_nonzero() == 0:
		cos_dis = 1.0
		cos_sim = 0.0
		DWCS = 0.0
		DWCS_L1 = 0.0
	else:
		cos_sim = fast_cosine_similarities(vector)
		cos_dis = 1 - cos_sim
		DWCS = cos_sim / (euc_dis + 1)
		DWCS_L1 = cos_sim / (euc_dis_normL1 + 1) 
	# print('{}\t{}\t{}\t{}\t{}'.format(cos_dis, euc_dis, cos_sim, DWCS, DWCS_L1))
	return (cos_dis, euc_dis, cos_sim, DWCS, DWCS_L1)

def complexComparing(obj1, obj2):
	start = time.time()
	alfa = [0.3, 0.2, 0.25, 0.15, 0.1] # instructions, registers, bad functions, vars, counter of [imm, mem, call, bads, vars]
	cmpVec1 = compareVectors(denseVector(obj1['a']), denseVector(obj2['a'])) # tf-idf bigram [instructions]
	cmpVec2 = compareVectors(denseVector(obj1['b']), denseVector(obj2['b'])) # tf-idf bigram [registers]
	cmpVec3 = compareVectors(denseVector(obj1['c']), denseVector(obj2['c'])) # binary bow unigram [bad functions]
	cmpVec4 = compareVectors(denseVector(obj1['d']), denseVector(obj2['d'])) # bow unigram [vars]
	cmpVec5 = compareVectors(denseVector(obj1['e']), denseVector(obj2['e'])) # counter of [imm, mem, call, bads, vars]
	resultCos = round(cmpVec1[0] * alfa[0] + cmpVec2[0] * alfa[1] + cmpVec3[0] * alfa[2] + cmpVec4[0] * alfa[3] + cmpVec5[0] * alfa[4], 2)
	resultEuc = round(cmpVec1[1] * alfa[0] + cmpVec2[1] * alfa[1] + cmpVec3[1] * alfa[2] + cmpVec4[1] * alfa[3] + cmpVec5[1] * alfa[4], 2)
	resultSimCos = round(cmpVec1[2] * alfa[0] + cmpVec2[2] * alfa[1] + cmpVec3[2] * alfa[2] + cmpVec4[2] * alfa[3] + cmpVec5[2] * alfa[4], 2)
	resultDWSimCos = round(cmpVec1[3] * alfa[0] + cmpVec2[3] * alfa[1] + cmpVec3[3] * alfa[2] + cmpVec4[3] * alfa[3] + cmpVec5[3] * alfa[4], 2)
	resultDWSimCosL1 = round(cmpVec1[4] * alfa[0] + cmpVec2[4] * alfa[1] + cmpVec3[4] * alfa[2] + cmpVec4[4] * alfa[3] + cmpVec5[4] * alfa[4], 2)
	resultDist = round(0.5 * resultCos + 0.5 * resultEuc, 2)
	resultMetric = round((resultDWSimCos+resultDWSimCosL1) / 2, 2)
	stop = time.time()
	print('[{} sec.] Dist = {}, SimCos = {}, DWCS = {}, DWCS_L1 = {}, !resultMetric = {}'.format(round(stop - start, 1), resultDist, resultSimCos, resultDWSimCos, resultDWSimCosL1, resultMetric))
	return (resultDist, resultSimCos, resultDWSimCos, resultDWSimCosL1, resultMetric)

def sparseVector(dv):
	sv = {}
	sv['len'] = len(dv)
	sv['data'] = {n: val for n, val in enumerate(dv) if val}
	return sv

def denseVector(sv):
	row = []
	col = []
	data = []
	for i in sv['data']:
		data.append(sv['data'][i])
		row.append(i)
		col.append(0)
	dv = sparse.csr_matrix((data, (col, row)), shape=(1, sv['len']))
	return dv

def saveModel(vector, sample):
	with open(modelPath+'sparseVector_{}.pickle'.format(sample), 'ab') as f: pickle.dump(vector, f, protocol=pickle.HIGHEST_PROTOCOL)
	return 0

def loadModel(sample):
	objs = []
	with open(modelPath+'sparseVector_{}.pickle'.format(sample), 'rb') as f:
		while 1:
			try: objs.append(pickle.load(f))
			except EOFError: break
	return objs
'''------</functions>------'''

'''------<training>------'''
def training(name, binary, pattern=''):
	print('Training model {} on binary "{}" ...'.format(name, binary))
	vuln = getVulnFunc(binaryPath+binary, 'aaa', pattern)
	ppi = getPseudoIntructionsNgram(vuln['data'], 2)
	vector_a = getVectorByTfIdf(ppi['instr'], ppi['instr_count'], spacesPath+'instructions_bigram_extended.txt', spacesPath+'idf_instructions_bigram.txt')
	# vector_a = getVectorByCounter(ppi['instr'], spacesPath+'instructions_bigram_extended.txt')
	vector_b = getVectorByTfIdf(ppi['reg'], ppi['reg_count'], spacesPath+'registers_bigram_extended.txt', spacesPath+'idf_registers_bigram.txt')
	# vector_b = getVectorByCounter(ppi['reg'], spacesPath+'registers_bigram_extended.txt')
	vector_c = getVectorByCounter(vuln['badFuncs'], spacesPath+'vulnApiFuncs.txt')
	vector_d = getSparseVector(vuln['vars'], 1048576) # 1MB = 1048576B
	vector_e = [ppi['imm'], ppi['mem'], ppi['call'], len(vuln['badFuncs']), len(vuln['vars'])]
	mainVector = {'a': sparseVector(vector_a), 'b': sparseVector(vector_b), 'c': sparseVector(vector_c), 'd': vector_d, 'e': sparseVector(vector_e)}
	saveModel(mainVector, '{}'.format(name))

def fastTraining(name, binary, pattern=''):
	funcs = getAllFuncs(binaryPath+binary, 'aa', pattern)
	with open(binaryPath+'{}.txt'.format(binary)) as f: trainingList = [i.replace('\n', '') for i in f.readlines()]
	print('Training model {} on binary "{}" ...'.format(name, binary))
	for f in funcs:
		if f.replace('sym.', '') in trainingList:
			print('Function {} - OK'.format(f))
			ppi = getPseudoIntructionsNgram(funcs[f]['data'], 2)
			vector_a = getVectorByTfIdf(ppi['instr'], ppi['instr_count'], spacesPath+'instructions_bigram_extended.txt', spacesPath+'idf_instructions_bigram.txt')
			# vector_a = getVectorByCounter(ppi['instr'], spacesPath+'instructions_bigram_extended.txt')
			vector_b = getVectorByTfIdf(ppi['reg'], ppi['reg_count'], spacesPath+'registers_bigram_extended.txt', spacesPath+'idf_registers_bigram.txt')
			# vector_b = getVectorByCounter(ppi['reg'], spacesPath+'registers_bigram_extended.txt')
			vector_c = getVectorByCounter(funcs[f]['badFuncs'], spacesPath+'vulnApiFuncs.txt')
			vector_d = getSparseVector(funcs[f]['vars'], 1048576) # 1MB = 1048576B
			vector_e = [ppi['imm'], ppi['mem'], ppi['call'], len(funcs[f]['badFuncs']), len(funcs[f]['vars'])]
			mainVector = {'a': sparseVector(vector_a), 'b': sparseVector(vector_b), 'c': sparseVector(vector_c), 'd': vector_d, 'e': sparseVector(vector_e)} # sum of length: 1394761 + 21609 + 78 + MAX10485760 + 4
			saveModel(mainVector, '{}'.format(name))
'''------</training>------'''

'''------<selfTesting>------'''
def smokeTest(model):
	obj = loadModel(model)
	first = obj[0]
	for i in obj: complexComparing(i, first)
'''------</selfTesting>------'''

'''------<testing>------'''
def testing(program, model, pattern='', windowSize=0):
	def inner(function):
		start = time.time()
		ppi = getPseudoIntructionsNgram(function['data'], 2)
		vector_a = getVectorByTfIdf(ppi['instr'], ppi['instr_count'], spacesPath+'instructions_bigram_extended.txt', spacesPath+'idf_instructions_bigram.txt')
		# vector_a = getVectorByCounter(ppi['instr'], spacesPath+'instructions_bigram_extended.txt')
		vector_b = getVectorByTfIdf(ppi['reg'], ppi['reg_count'], spacesPath+'registers_bigram_extended.txt', spacesPath+'idf_registers_bigram.txt')
		# vector_b = getVectorByCounter(ppi['reg'], spacesPath+'registers_bigram_extended.txt')
		vector_c = getVectorByCounter(function['badFuncs'], spacesPath+'vulnApiFuncs.txt')
		vector_d = getSparseVector(function['vars'], 1048576) # 1MB = 1048576B
		vector_e = [ppi['imm'], ppi['mem'], ppi['call'], len(function['badFuncs']), len(function['vars'])]
		mainVector = {'a': sparseVector(vector_a), 'b': sparseVector(vector_b), 'c': sparseVector(vector_c), 'd': vector_d, 'e': sparseVector(vector_e)} # sum of length: 1394761 + 21609 + 78 + MAX10485760 + 4
		tmp = []
		for i in range(len(obj)): tmp.append(complexComparing(obj[i], mainVector))
		stop = time.time()
		bestResults = (tmp[np.argmin([i[0] for i in tmp])], tmp[np.argmax([i[1] for i in tmp])], tmp[np.argmax([i[2] for i in tmp])], tmp[np.argmax([i[3] for i in tmp])], tmp[np.argmax([i[4] for i in tmp])])
		bestResultsAmongAll = (bestResults[0][0], bestResults[1][1], bestResults[2][2], bestResults[3][3], bestResults[4][4])
		# print(bestResults)
		# print('Function <{}> ({} sec.) -> [minDist: {}], [maxCosSim: {}], [maxAdjCosSim: {}], [maxDWSimCos: {}], [maxModDWCS: {}]'.format(f, round(stop - start, 1), bestResults[0], bestResults[1], bestResults[2], bestResults[3], bestResults[4]))
		print('Function <{}> ({} sec.) -> [minDist: {}], [maxCosSim: {}], [maxDWCosSim: {}], [maxDWCS_L1: {}], [!maxResultMetric: {}]'.format(f, round(stop - start, 1), bestResultsAmongAll[0], bestResultsAmongAll[1], bestResultsAmongAll[2], bestResultsAmongAll[3], bestResultsAmongAll[4]))
		return bestResultsAmongAll

	print('Testing program "{}" on model "{}" ...'.format(program, model))
	obj = loadModel(model)
	funcs = getAllFuncs('./test/{}'.format(program), 'aa', pattern)
	with open(binaryPath+'{}.txt'.format('vulnerabilityLib')) as f: trainingList = [i.replace('\n', '') for i in f.readlines()]
	for f in funcs:
		if windowSize <= 0 or windowSize >= len(funcs[f]['meta']):
			result = inner(funcs[f])
		else:
			maxWndIter = len(funcs[f]['meta'])-windowSize+1
			temp = []
			for offset in range(maxWndIter):
				print('Iteration {}/{}'.format(offset+1, maxWndIter))
				if offset != maxWndIter-1: window = funcs[f]['data'][funcs[f]['meta'][offset]*2:funcs[f]['meta'][offset+windowSize]*2]
				else: window = funcs[f]['data'][funcs[f]['meta'][offset]*2:len(funcs[f]['data'])]
				fCopy = funcs[f].copy()
				fCopy['data'] = window
				result = inner(fCopy)
				temp.append(result)
			bestResults = (temp[np.argmin([i[0] for i in temp])], temp[np.argmax([i[1] for i in temp])], temp[np.argmax([i[2] for i in temp])], temp[np.argmax([i[3] for i in temp])], temp[np.argmax([i[4] for i in temp])])
			print('Best results -> [minDist: {}], [maxCosSim: {}], [maxDWCosSim: {}], [maxDWCS_L1: {}], [!maxResultMetric: {}]'.format(bestResults[0], bestResults[1], bestResults[2], bestResults[3], bestResults[4]))
'''------</testing>------'''

if __name__ == '__main__':
	# fastTraining('sbof_vulns_tfidf', 'vulnerabilityLib')
	# training('sbof_vulns_tfidf', 'libical.so.0.47.0', 'icalrecur_add_bydayrules')
	# smokeTest('sbof_vulns')
	testing('test', 'sbof_vulns_tfidf', 'return_input', 0)