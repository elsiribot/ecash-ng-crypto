# Builds of the scheme description.
#   make            -> colour A4, black & white A4, black & white A5, and the A5 2-up sheets
#   make clean      -> remove LaTeX build files
SRC   := Fedimint_Blinded_eCash.tex
LMK   := latexmk -pdf -interaction=nonstopmode -halt-on-error

all: Fedimint_Blinded_eCash.pdf Fedimint_Blinded_eCash_bw.pdf Fedimint_Blinded_eCash_bw_a5.pdf Fedimint_Blinded_eCash_bw_a5_2up.pdf

Fedimint_Blinded_eCash.pdf: $(SRC)
	$(LMK) $(SRC)

Fedimint_Blinded_eCash_bw.pdf: $(SRC)
	$(LMK) -jobname=$(basename $@) -pdflatex='pdflatex %O "\def\BW{1}\input{%S}"' $(SRC)

# A5 pages with a wide left margin for clip binding
Fedimint_Blinded_eCash_bw_a5.pdf: $(SRC)
	$(LMK) -jobname=$(basename $@) -pdflatex='pdflatex %O "\def\BW{1}\def\AFIVE{1}\input{%S}"' $(SRC)

# Two A5 pages per landscape A4 sheet in cut-and-stack order: print single-sided,
# cut every sheet in half, put the right-hand stack under the left-hand stack.
Fedimint_Blinded_eCash_bw_a5_2up.pdf: Fedimint_Blinded_eCash_bw_a5.pdf impose_a5_2up.tex
	$(LMK) -jobname=$(basename $@) impose_a5_2up.tex

clean:
	latexmk -c
	rm -f *.aux *.log *.out *.fls *.fdb_latexmk *.toc

.PHONY: all clean
