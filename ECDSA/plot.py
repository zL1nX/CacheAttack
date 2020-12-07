import sys
from matplotlib import pyplot as plt
import numpy as np
import Levenshtein as ls
from functools import reduce


def convert(x):
	return '1' if int(x) > 0 else '0'

k = "300000005000500030005000000007000070000500000100000300007000050000005000100030001000500010000700010003000100010003000050000300010007000001000500000100070001000300003000070001000050003000050007000300030000100050000000700010007000700000000010000007000030001"
bink = ''.join(list(map(convert, k)))

def running_mean(x, N):
	x = [float(i) for i in x]
	cumsum = np.cumsum(np.insert(x, 0, 0)) 
	return list((cumsum[N:] - cumsum[:-N]) / float(N))


def hamming_weight(s):
	return sum(list(map(int, s)))

def hamming_distance(a, b):
	la, lb = len(a), len(b)
	l = la if la < lb else lb
	return sum([(int(i) ^ int(j)) for i, j in zip(a[:l], b[:l])])

def find_lcsubstr(s1, s2): 
	m=[[0 for i in range(len(s2)+1)]  for j in range(len(s1)+1)]  #生成0矩阵，为方便后续计算，比字符串长度多了一列
	mmax=0   
	p=0  
	for i in range(len(s1)):
		for j in range(len(s2)):
			if s1[i]==s2[j]:
				m[i+1][j+1]=m[i][j]+1
				if m[i+1][j+1]>mmax:
					mmax=m[i+1][j+1]
					p=i+1
	res = s1[p - mmax:p]
	return p- mmax, mmax, res

def find_lcseque(s1, s2): 
	m = [ [ 0 for x in range(len(s2)+1) ] for y in range(len(s1)+1) ] 
	d = [ [ None for x in range(len(s2)+1) ] for y in range(len(s1)+1) ] 
	
	ind = []
	for p1 in range(len(s1)): 
		for p2 in range(len(s2)): 
			if s1[p1] == s2[p2]:           
				m[p1+1][p2+1] = m[p1][p2]+1
				d[p1+1][p2+1] = 'ok'          
			elif m[p1+1][p2] > m[p1][p2+1]: 
				m[p1+1][p2+1] = m[p1+1][p2] 
				d[p1+1][p2+1] = 'left'          
			else:                           
				m[p1+1][p2+1] = m[p1][p2+1]   
				d[p1+1][p2+1] = 'up'         
	(p1, p2) = (len(s1), len(s2)) 
	s = [] 
	while m[p1][p2]:    
		c = d[p1][p2]
		if c == 'ok':   
			s.append(s1[p1-1])
			ind.append(p1-1)
			p1-=1
			p2-=1 
		if c =='left':  
			p2 -= 1
		if c == 'up':   
			p1 -= 1
	s.reverse()
	ind.reverse()
	res = ''.join(s)
	return res, ind


def bit_print(seq):
	assert len(seq[0]) > 0
	print_list = [str(i[1]) for i in seq]
	print_str = ''.join(print_list)
	lcs = find_lcseque(print_str, bink)[0]
	l = min(len(lcs), len(bink))
	_l = min(len(print_str), len(bink))
	print("[*]Levnshtesin Distance is: ", ls.distance(lcs[:l], bink[:l]))

def compress(seq):
	op_seq, res_seq = [], []

	start, end = 1, 0
	clusters = []
	i = 1
	while i < len(seq) - 1: # identity the start and ending point
		if seq[i][0] - seq[i - 1][0] >= 200000:
			start = i
		elif seq[i + 1][0] - seq[i][0] >= 150000:
			end = i
			clusters.append([start, end])
		i += 1
	mmax, flag = 0, 0
	if len(clusters) != 0:
		for i in range(len(clusters)):
			d = clusters[i][1] - clusters[i][0] 
			if d < 130 and d > mmax:
				mmax = d
				flag = i
		op_seq = seq[:clusters[flag][0]] + seq[clusters[flag][1] + 1:]
	else:
		op_seq = seq
	

	return op_seq


def filter_sequence(seq):
	op_seq, res_seq = [], []
	i = 0
	while i < len(seq) - 1:
		t = seq[i]
		if seq[i][1] == 1 and seq[i + 1][1] == 0 and seq[i + 1][0] - seq[i][0] == 0 : # nearly the same
			i += 1
			# continue
		elif seq[i][1] == 1 and seq[i + 1][1] == 0 and seq[i + 1][0] - seq[i][0] < 3000: 
			i += 1
		elif seq[i][1] == 1 and seq[i + 1][1] == 1:
			seq[i + 1][1] = 0
		op_seq.append(t)
		i += 1
	if i == len(seq) - 1:
		op_seq.append(seq[-1])
	
	bit_print(op_seq)
	return op_seq


def merge(peak_data):
	l = list(peak_data.values())
	merged_l = []
	if len(l) == 2:
		p, q = 0,0 
		while p < len(l[0]) and q < len(l[1]):
			if l[0][p][0] < l[1][q][0]:
				merged_l.append([l[0][p][0], l[0][p][1]])
				p += 1
			elif l[0][p][0] == l[1][q][0]:
				merged_l.append([l[0][p][0], 1])
				merged_l.append([l[0][p][0], 0])
				p += 1
				q += 1
			else:
				merged_l.append([l[1][q][0], l[1][q][1]])
				q += 1
			

		while p < len(l[0]): 
			merged_l.append([l[0][p][0], l[0][p][1]])
			p += 1
		while q < len(l[1]): 
			merged_l.append([l[1][q][0], l[1][q][1]])
			q += 1
	else:
		print("Probe too much")

	return merged_l


def extract_sequence(peak_data):
	ml = merge(peak_data)
	temp = ''.join([str(i[1]) for i in ml])
	temp_l = min(len(temp), len(bink))

	processed = filter_sequence(compress(ml))
	peak_seq = ''.join([str(t[1]) for t in processed])
	
	res, ind = find_lcseque(peak_seq, bink)
	print("[*]Captured Subsequence (Processed) is: ", res)



def plot(data, fname):
	# print(len(data['R']))
	plt.rcParams["figure.figsize"] = [16,3]
	peak_data = {}
	
	for label in data:
		flag = 0 if label == "Dbl" else 1
		x = [int(i[0]) for i in data[label]]
		_y = [int(i[1]) for i in data[label]]
		y = running_mean(_y, 1)
		peak_data[label] = [(x[i], flag) for i in range(len(y)) if y[i] < 130]
		y.extend([200] * (len(x) - len(y)))
		fft = np.fft.fft(y)
		probe_data = list(map(abs, np.fft.ifft(fft)))

		plt.plot(x, probe_data , "o", label=label, alpha=1.0)

	extract_sequence(peak_data)
	plt.legend(loc='best')
	plt.xlabel('Time')
	plt.ylabel('Latency')
	plt.show()
	# print("Saved to " + fname)


def wrap_up():
	data = {}
	start = False
	counter = 1
	for line in sys.stdin:
		line = line.rstrip("\n")
		if (line == "END"):
			plot(data, str(counter) + '.png')
			counter += 1
			data = {}
			start = False
		elif (line == "START"):
			start = True
		elif start:
			label, time, probe_time = line.split(",")
			if (label not in data.keys()):
				data[label] = []
			data[label].append((time, probe_time))

wrap_up()