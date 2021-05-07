import json, pickle, numpy as np, pandas as pd, matplotlib, matplotlib.pyplot as plt
from scipy import spatial, sparse
from sklearn.decomposition import PCA, TruncatedSVD
from main import loadModel, denseVector

def getPCA(model):
	obj = loadModel(model)
	X = sparse.hstack([denseVector(obj[0]['a']), denseVector(obj[0]['b']), denseVector(obj[0]['c']), denseVector(obj[0]['d']), denseVector(obj[0]['e'])])
	for i in range(1, len(obj)): X = sparse.vstack([X, sparse.hstack([denseVector(obj[i]['a']), denseVector(obj[i]['b']), denseVector(obj[i]['c']), denseVector(obj[i]['d']), denseVector(obj[i]['e'])])])
	df = pd.DataFrame.sparse.from_spmatrix(X)
	print(df.info(memory_usage='deep'))
	df=df.sparse.to_dense()
	pca = PCA(n_components=2)
	principalComponents = pca.fit_transform(df)
	return principalComponents

principalComponentsVulns = getPCA('sbof_vulns_tfidf')
# principalComponentsBenigns = getPCA('sbof_benigns')
pdfVulns = pd.concat([pd.DataFrame(data = principalComponentsVulns , columns = ['PC_1', 'PC_2']), pd.DataFrame({'target':['vulns' for i in range(len(principalComponentsVulns))]})], axis = 1)
# pdfBenigns = pd.concat([pd.DataFrame(data = principalComponentsBenigns , columns = ['PC_1', 'PC_2']), pd.DataFrame({'target':['benigns' for i in range(len(principalComponentsBenigns))]})], axis = 1)
finalDf = pdfVulns
# finalDf = pd.concat([pdfVulns, pdfBenigns], ignore_index = True)
# print(finalDf)

fig = plt.figure(figsize=(12, 7))
ax = fig.add_subplot(1,1,1) 
ax.set_xlabel('Principal Component 1', fontsize = 15)
ax.set_ylabel('Principal Component 2', fontsize = 15)
ax.set_title('2 Component PCA', fontsize = 20)
targets = ['vulns', 'benigns']
colors = ['r', 'g', 'b']
for target, color in zip(targets,colors):
    indicesToKeep = finalDf['target'] == target
    ax.scatter(finalDf.loc[indicesToKeep, 'PC_1'], finalDf.loc[indicesToKeep, 'PC_2'], c = color)
ax.legend(targets)
ax.grid()
plt.show()