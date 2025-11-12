(function () {
    function initQuiz(page) {
        const pageEl = page.$el || page.el; // pega a página atual do F7
        const questionContainer = pageEl.querySelector("#question-container");
        const questionEl = pageEl.querySelector(".quiz-question");
        const optionsContainer = pageEl.querySelector(".quiz-options");
        const checkBtn = pageEl.querySelector("#check-answer");
        const resultContainer = pageEl.querySelector("#result-container");
        const resultText = pageEl.querySelector("#result-text");
        const restartBtn = pageEl.querySelector("#restart-btn");

        if (!questionEl || !optionsContainer || !checkBtn) {
            console.warn("Quiz: elementos não encontrados.");
            return;
        }

        // Perguntas
        const questions = [
            { question: "Quanto é 7 × 8?", options: ["54", "56", "64", "48"], answerIndex: 1 },
            { question: "Qual é a raiz quadrada de 81?", options: ["7", "8", "9", "10"], answerIndex: 2 },
            { question: "Quanto é 12 ÷ 3?", options: ["3", "4", "5", "6"], answerIndex: 1 },
            { question: "Quanto é 15 + 27?", options: ["42", "40", "45", "44"], answerIndex: 0 }
        ];

        let currentIndex = 0;
        let score = 0;
        let selectedIndex = null;

        // Carrega a pergunta atual
        function loadQuestion() {
            selectedIndex = null;
            checkBtn.dataset.state = "check";
            checkBtn.textContent = "Verificar Resposta";

            const q = questions[currentIndex];
            questionEl.textContent = q.question;

            // Atualiza textos dos botões
            const btns = optionsContainer.querySelectorAll(".quiz-option");
            btns.forEach((btn, i) => {
                btn.textContent = q.options[i] ?? "";
                btn.dataset.index = i;
                btn.disabled = false;
                btn.classList.remove("selected", "correct", "incorrect");
                btn.style.pointerEvents = "";
            });

            if (resultContainer) resultContainer.style.display = "none";
            if (questionContainer) questionContainer.style.display = "";
            checkBtn.style.display = "";
        }

        // Seleção de opção
        optionsContainer.addEventListener("click", function (ev) {
            const btn = ev.target.closest(".quiz-option");
            if (!btn || btn.disabled) return;

            const all = optionsContainer.querySelectorAll(".quiz-option");
            all.forEach(b => b.classList.remove("selected"));
            btn.classList.add("selected");
            selectedIndex = parseInt(btn.dataset.index, 10);
        });

        // Verificar/Próxima
        checkBtn.addEventListener("click", function () {
            const state = checkBtn.dataset.state || "check";

            if (state === "check") {
                if (selectedIndex === null) {
                    if (window.app && app.toast) {
                        app.toast.create({ text: "Selecione uma opção primeiro", closeTimeout: 2000 }).open();
                    } else {
                        alert("Selecione uma opção primeiro");
                    }
                    return;
                }

                const q = questions[currentIndex];
                const correct = q.answerIndex;
                const btns = optionsContainer.querySelectorAll(".quiz-option");

                btns.forEach((b, i) => {
                    b.disabled = true;
                    b.style.pointerEvents = "none";
                    b.classList.remove("selected");
                    if (i === correct) b.classList.add("correct");
                    else if (i === selectedIndex) b.classList.add("incorrect");
                });

                if (selectedIndex === correct) score++;

                checkBtn.dataset.state = "next";
                checkBtn.textContent = (currentIndex < questions.length - 1) ? "Próxima" : "Finalizar";
                return;
            }

            // Próxima pergunta
            currentIndex++;
            if (currentIndex < questions.length) loadQuestion();
            else showResult();
        });

        function showResult() {
            if (questionContainer) questionContainer.style.display = "none";
            if (checkBtn) checkBtn.style.display = "none";
            if (resultContainer) {
                resultContainer.style.display = "block";
                resultText.textContent = `Você acertou ${score} de ${questions.length} questões!`;
                resultContainer.scrollIntoView({ behavior: "smooth", block: "center" });
            }
        }

        restartBtn && restartBtn.addEventListener("click", function () {
            currentIndex = 0;
            score = 0;
            selectedIndex = null;
            loadQuestion();
        });

        // Inicia
        loadQuestion();
    }

    // Evento do F7
    document.addEventListener('page:init', function (e) {
        if (e.detail.name === 'quiz-matematica') {
            initQuiz(e.detail);
        }
    });
})();
