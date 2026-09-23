name: Generate VLESS subscriptions

on:
  workflow_dispatch:
  schedule:
    # GitHub Actions 使用 UTC
    # 每小时第 24 分钟执行
    - cron: '24 */1 * * *'


# ============================================================
# 顶层权限
# ============================================================

permissions:
  contents: read


# ============================================================
# 防止多个运行同时修改历史池 / README / Pages
# ============================================================

concurrency:
  group: pages
  cancel-in-progress: false


jobs:

  # ==========================================================
  # Generate
  # ==========================================================

  generate:

    if: >-
      github.ref ==
      format('refs/heads/{0}', github.event.repository.default_branch)

    runs-on: ubuntu-latest
    timeout-minutes: 30

    permissions:
      contents: write

    steps:

      # ------------------------------------------------------
      # Checkout
      # ------------------------------------------------------

      - name: Checkout
        uses: actions/checkout@v4


      # ------------------------------------------------------
      # Python
      # ------------------------------------------------------

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
          cache-dependency-path: requirements.txt


      # ------------------------------------------------------
      # 安装依赖
      # ------------------------------------------------------

      - name: Install dependencies
        run: |
          python -m pip install \
            --disable-pip-version-check \
            -r requirements.txt


      # ======================================================
      # 生成 TXT + YAML + 历史 IP
      # ======================================================

      - name: Generate subscriptions
        run: |
          python -u src/generator.py


      # ======================================================
      # 验证输出
      # ======================================================

      - name: Validate output
        shell: bash
        run: |

          set -euo pipefail

          if [ ! -f "output/all.txt" ]; then
            echo "[ERROR] output/all.txt not found."
            exit 1
          fi

          if [ ! -f "output/all.yaml" ]; then
            echo "[ERROR] output/all.yaml not found."
            exit 1
          fi


          TXT_COUNT=$(
            base64 -d output/all.txt 2>/dev/null \
              | awk '
                  /^vless:\/\// {
                    n++
                  }
                  END {
                    print n+0
                  }
                '
          )


          YAML_COUNT=$(
            awk '
              /^[[:space:]]*-[[:space:]]name:/ {
                n++
              }
              END {
                print n+0
              }
            ' output/all.yaml
          )


          echo "[CHECK] TXT nodes : $TXT_COUNT"
          echo "[CHECK] YAML nodes: $YAML_COUNT"


          if [ "$TXT_COUNT" -le 0 ]; then
            echo "[ERROR] all.txt contains zero VLESS nodes."
            exit 1
          fi


          if [ "$YAML_COUNT" -le 0 ]; then
            echo "[ERROR] all.yaml contains zero Mihomo nodes."
            exit 1
          fi


          if [ "$TXT_COUNT" -ne "$YAML_COUNT" ]; then
            echo "[ERROR] TXT/YAML node count mismatch."
            exit 1
          fi


          echo "[OK] output validation passed."


      # ======================================================
      # 生成统计信息
      # ======================================================

      - name: Calculate statistics
        id: stats
        shell: bash
        run: |

          set -euo pipefail


          count_txt_nodes() {

            local file="$1"

            if [ -f "$file" ]; then

              base64 -d "$file" 2>/dev/null \
                | awk '
                    /^vless:\/\// {
                      n++
                    }
                    END {
                      print n+0
                    }
                  '

            else

              echo "0"

            fi
          }


          count_yaml_nodes() {

            local file="$1"

            if [ -f "$file" ]; then

              awk '
                /^[[:space:]]*-[[:space:]]name:/ {
                  n++
                }
                END {
                  print n+0
                }
              ' "$file"

            else

              echo "0"

            fi
          }


          # ==================================================
          # 总节点
          # ==================================================

          TOTAL_TXT=$(
            count_txt_nodes "output/all.txt"
          )

          TOTAL_YAML=$(
            count_yaml_nodes "output/all.yaml"
          )


          # ==================================================
          # 历史池
          # ==================================================

          if [ -f "data/ip_history.json" ]; then

            HISTORY_COUNT=$(
              python -c \
              'import json; print(len(json.load(open("data/ip_history.json", encoding="utf-8"))))' \
              2>/dev/null || echo "0"
            )

          else

            HISTORY_COUNT=0

          fi


          HISTORY_LIMIT=$(
            python -c \
            "import yaml; cfg = yaml.safe_load(open('config/config.yml', encoding='utf-8')); print(cfg.get('history', {}).get('max_pool_size', 5000))" \
            2>/dev/null || echo "5000"
          )


          # ==================================================
          # 输出变量
          # ==================================================

          {
            echo "total_txt=$TOTAL_TXT"
            echo "total_yaml=$TOTAL_YAML"
            echo "history_count=$HISTORY_COUNT"
            echo "history_limit=$HISTORY_LIMIT"
          } >> "$GITHUB_OUTPUT"


          # ==================================================
          # 写入临时统计文件
          #
          # 后面的 Summary / README 都使用这个结果。
          # ==================================================

          {
            echo "REGION_HK_TXT=$(count_txt_nodes output/hk.txt)"
            echo "REGION_HK_YAML=$(count_yaml_nodes output/hk.yaml)"

            echo "REGION_JP_TXT=$(count_txt_nodes output/jp.txt)"
            echo "REGION_JP_YAML=$(count_yaml_nodes output/jp.yaml)"

            echo "REGION_SG_TXT=$(count_txt_nodes output/sg.txt)"
            echo "REGION_SG_YAML=$(count_yaml_nodes output/sg.yaml)"

            echo "REGION_KR_TXT=$(count_txt_nodes output/kr.txt)"
            echo "REGION_KR_YAML=$(count_yaml_nodes output/kr.yaml)"

            echo "REGION_TW_TXT=$(count_txt_nodes output/tw.txt)"
            echo "REGION_TW_YAML=$(count_yaml_nodes output/tw.yaml)"

            echo "REGION_US_TXT=$(count_txt_nodes output/us.txt)"
            echo "REGION_US_YAML=$(count_yaml_nodes output/us.yaml)"

            echo "REGION_OTHER_TXT=$(count_txt_nodes output/other.txt)"
            echo "REGION_OTHER_YAML=$(count_yaml_nodes output/other.yaml)"

            echo "ISP_CMCC_TXT=$(count_txt_nodes output/cmcc.txt)"
            echo "ISP_CMCC_YAML=$(count_yaml_nodes output/cmcc.yaml)"

            echo "ISP_CU_TXT=$(count_txt_nodes output/cu.txt)"
            echo "ISP_CU_YAML=$(count_yaml_nodes output/cu.yaml)"

            echo "ISP_CT_TXT=$(count_txt_nodes output/ct.txt)"
            echo "ISP_CT_YAML=$(count_yaml_nodes output/ct.yaml)"

            echo "TOTAL_TXT=$TOTAL_TXT"
            echo "TOTAL_YAML=$TOTAL_YAML"
            echo "HISTORY_COUNT=$HISTORY_COUNT"
            echo "HISTORY_LIMIT=$HISTORY_LIMIT"

          } > /tmp/cf-ip-stats.env


          cat /tmp/cf-ip-stats.env


      # ======================================================
      # OUTPUT
      # ======================================================

      - name: OUTPUT
        shell: bash
        run: |

          set -euo pipefail

          set -a
          set -a
          source /tmp/cf-ip-stats.env
          set +a
          set +a


          echo ""
          echo "========================================"
          echo "          CF-IP OUTPUT"
          echo "========================================"
          echo ""

          echo "生成时间：$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
          echo ""

          echo "历史 IP 池：$HISTORY_COUNT"
          echo "历史池上限：$HISTORY_LIMIT"
          echo "淘汰规则：连续 3 次健康检查失败"
          echo ""

          echo "最终 VLESS 节点：$TOTAL_TXT"
          echo "最终 Mihomo 节点：$TOTAL_YAML"
          echo ""

          echo "----------------------------------------"
          printf "%-18s %8s %8s\n" \
            "分类" \
            "TXT" \
            "YAML"

          echo "----------------------------------------"


          echo "地区："

          printf "%-18s %8s %8s\n" \
            "hk" \
            "$REGION_HK_TXT" \
            "$REGION_HK_YAML"

          printf "%-18s %8s %8s\n" \
            "jp" \
            "$REGION_JP_TXT" \
            "$REGION_JP_YAML"

          printf "%-18s %8s %8s\n" \
            "sg" \
            "$REGION_SG_TXT" \
            "$REGION_SG_YAML"

          printf "%-18s %8s %8s\n" \
            "kr" \
            "$REGION_KR_TXT" \
            "$REGION_KR_YAML"

          printf "%-18s %8s %8s\n" \
            "tw" \
            "$REGION_TW_TXT" \
            "$REGION_TW_YAML"

          printf "%-18s %8s %8s\n" \
            "us" \
            "$REGION_US_TXT" \
            "$REGION_US_YAML"

          printf "%-18s %8s %8s\n" \
            "other" \
            "$REGION_OTHER_TXT" \
            "$REGION_OTHER_YAML"


          echo ""

          echo "运营商："

          printf "%-18s %8s %8s\n" \
            "cmcc" \
            "$ISP_CMCC_TXT" \
            "$ISP_CMCC_YAML"

          printf "%-18s %8s %8s\n" \
            "cu" \
            "$ISP_CU_TXT" \
            "$ISP_CU_YAML"

          printf "%-18s %8s %8s\n" \
            "ct" \
            "$ISP_CT_TXT" \
            "$ISP_CT_YAML"


          echo "----------------------------------------"

          printf "%-18s %8s %8s\n" \
            "ALL" \
            "$TOTAL_TXT" \
            "$TOTAL_YAML"

          echo "----------------------------------------"
          echo ""


          PROBABLE_BASE="https://${{ github.repository_owner }}.github.io/${{ github.event.repository.name }}"


          echo "Pages："
          echo "${PROBABLE_BASE}/"
          echo ""

          echo "VLESS TXT："
          echo "${PROBABLE_BASE}/all.txt"
          echo ""

          echo "Mihomo YAML："
          echo "${PROBABLE_BASE}/all.yaml"
          echo ""

          echo "========================================"


      # ======================================================
      # GitHub Actions Summary
      # ======================================================

      - name: Generate Summary
        shell: bash
        run: |

          set -euo pipefail

          source /tmp/cf-ip-stats.env


          {
            echo "# 🚀 CF-IP 生成结果"
            echo ""

            echo "**生成时间：**"
            echo ""
            echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
            echo ""


            echo "## 📊 地区节点统计"
            echo ""

            echo "| 地区 | VLESS TXT | Mihomo YAML |"
            echo "|:---|---:|---:|"

            echo "| 🇭🇰 HK | ${REGION_HK_TXT} | ${REGION_HK_YAML} |"
            echo "| 🇯🇵 JP | ${REGION_JP_TXT} | ${REGION_JP_YAML} |"
            echo "| 🇸🇬 SG | ${REGION_SG_TXT} | ${REGION_SG_YAML} |"
            echo "| 🇰🇷 KR | ${REGION_KR_TXT} | ${REGION_KR_YAML} |"
            echo "| 🇹🇼 TW | ${REGION_TW_TXT} | ${REGION_TW_YAML} |"
            echo "| 🇺🇸 US | ${REGION_US_TXT} | ${REGION_US_YAML} |"
            echo "| 🌐 OTHER | ${REGION_OTHER_TXT} | ${REGION_OTHER_YAML} |"

            echo ""


            echo "## 📡 运营商节点统计"
            echo ""

            echo "| 运营商 | VLESS TXT | Mihomo YAML |"
            echo "|:---|---:|---:|"

            echo "| 📱 中国移动 CMCC | ${ISP_CMCC_TXT} | ${ISP_CMCC_YAML} |"
            echo "| 🔗 中国联通 CU | ${ISP_CU_TXT} | ${ISP_CU_YAML} |"
            echo "| ☎️ 中国电信 CT | ${ISP_CT_TXT} | ${ISP_CT_YAML} |"

            echo ""


            echo "## 🗃️ 历史 IP 池"
            echo ""

            echo "**${HISTORY_COUNT} / ${HISTORY_LIMIT} 个 IP**"
            echo ""

            echo "- 当前源 IP 与历史 IP 一起健康检查"
            echo "- 源站消失但仍健康的 IP 继续保留"
            echo "- 连续 3 次健康检查失败后淘汰"
            echo "- 历史池上限：${HISTORY_LIMIT}"

            echo ""


            echo "## 📦 总计"
            echo ""

            echo "**${TOTAL_TXT} 个 VLESS 节点**"
            echo ""

            echo "**${TOTAL_YAML} 个 Mihomo 节点**"
            echo ""

            echo "## 🌐 GitHub Pages"
            echo ""

            echo "部署完成后的真实地址见本次运行的 Deploy 任务摘要。"

          } >> "$GITHUB_STEP_SUMMARY"


      # ======================================================
      # 自动更新 README
      #
      # 只更新统计区块。
      #
      # 不写入动态生成时间，因此：
      # 如果节点数量没有变化，README 不产生 commit。
      # ======================================================
      - name: Update README statistics
        shell: bash
        run: |

          set -euo pipefail

          set -a
          source /tmp/cf-ip-stats.env
          set +a

          export \
            REGION_HK_TXT \
            REGION_HK_YAML \
            REGION_JP_TXT \
            REGION_JP_YAML \
            REGION_SG_TXT \
            REGION_SG_YAML \
            REGION_KR_TXT \
            REGION_KR_YAML \
            REGION_TW_TXT \
            REGION_TW_YAML \
            REGION_US_TXT \
            REGION_US_YAML \
            REGION_OTHER_TXT \
            REGION_OTHER_YAML \
            ISP_CMCC_TXT \
            ISP_CMCC_YAML \
            ISP_CU_TXT \
            ISP_CU_YAML \
            ISP_CT_TXT \
            ISP_CT_YAML \
            TOTAL_TXT \
            TOTAL_YAML \
            HISTORY_COUNT \
            HISTORY_LIMIT


          python <<'PY'

          from pathlib import Path
          import os


          readme = Path("README.md")

          if readme.exists():
              text = readme.read_text(encoding="utf-8")
          else:
              text = "# CF-IP 优化版\n"


          start_marker = "<!-- CF-IP-STATS:START -->"
          end_marker = "<!-- CF-IP-STATS:END -->"


          def env(name):
              return os.environ.get(name, "0")


          stats = f"""
          {start_marker}

          ## 📊 当前节点统计

          > 本区域由 GitHub Actions 自动更新。  
          > 仅当统计数据发生变化时才会产生 README 提交。

          ### 🌍 地区节点

          | 地区 | VLESS TXT | Mihomo YAML |
          |:---|---:|---:|
          | 🇭🇰 香港 HK | {env("REGION_HK_TXT")} | {env("REGION_HK_YAML")} |
          | 🇯🇵 日本 JP | {env("REGION_JP_TXT")} | {env("REGION_JP_YAML")} |
          | 🇸🇬 新加坡 SG | {env("REGION_SG_TXT")} | {env("REGION_SG_YAML")} |
          | 🇰🇷 韩国 KR | {env("REGION_KR_TXT")} | {env("REGION_KR_YAML")} |
          | 🇹🇼 台湾 TW | {env("REGION_TW_TXT")} | {env("REGION_TW_YAML")} |
          | 🇺🇸 美国 US | {env("REGION_US_TXT")} | {env("REGION_US_YAML")} |
          | 🌐 其他 OTHER | {env("REGION_OTHER_TXT")} | {env("REGION_OTHER_YAML")} |

          ### 📡 运营商节点

          | 运营商 | VLESS TXT | Mihomo YAML |
          |:---|---:|---:|
          | 📱 中国移动 CMCC | {env("ISP_CMCC_TXT")} | {env("ISP_CMCC_YAML")} |
          | 🔗 中国联通 CU | {env("ISP_CU_TXT")} | {env("ISP_CU_YAML")} |
          | ☎️ 中国电信 CT | {env("ISP_CT_TXT")} | {env("ISP_CT_YAML")} |

          ### 📦 总计

          - **VLESS：{env("TOTAL_TXT")} 个节点**
          - **Mihomo：{env("TOTAL_YAML")} 个节点**
          - **历史 IP 池：{env("HISTORY_COUNT")} / {env("HISTORY_LIMIT")}**

          > DE / CN 节点不纳入实际节点池及统计。

          {end_marker}
          """.strip()


          if start_marker in text and end_marker in text:

              before = text.split(start_marker, 1)[0].rstrip()
              after = text.split(end_marker, 1)[1].lstrip()

              if after:
                  new_text = (
                      before
                      + "\n\n"
                      + stats
                      + "\n\n"
                      + after
                  )
              else:
                  new_text = (
                      before
                      + "\n\n"
                      + stats
                      + "\n"
                  )

          else:

              new_text = (
                  text.rstrip()
                  + "\n\n"
                  + stats
                  + "\n"
              )


          readme.write_text(
              new_text,
              encoding="utf-8",
          )

          print("[OK] README statistics updated.")

          PY



      # ======================================================
      # 提交历史池 + README
      #
      # 注意：
      # 不会提交 output/
      # output/ 由 GitHub Pages artifact 部署。
      #
      # 不会添加 push trigger。
      # 因此这里 git push 后不会重新触发本 Workflow。
      # ======================================================

      - name: Save IP history and README
        shell: bash
        run: |

          set -euo pipefail


          git config user.name \
            "github-actions[bot]"

          git config user.email \
            "41898282+github-actions[bot]@users.noreply.github.com"


          if [ ! -f "data/ip_history.json" ]; then
            echo "[INFO] data/ip_history.json was not generated."
          fi


          git add \
            data/ip_history.json \
            README.md


          if git diff --cached --quiet; then

            echo "[INFO] IP history and README unchanged."

          else

            echo "[INFO] Updating IP history / README..."

            git commit \
              -m "chore: update IP history and statistics"

            git push

          fi


      # ======================================================
      # 上传 GitHub Pages artifact
      # ======================================================

      - name: Upload Pages artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: output


  # ==========================================================
  # Deploy
  # ==========================================================

  deploy:

    needs: generate

    runs-on: ubuntu-latest
    timeout-minutes: 10

    permissions:
      pages: write
      id-token: write

    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}


    steps:

      # ------------------------------------------------------
      # Deploy
      # ------------------------------------------------------

      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4


      # ======================================================
      # Deployment OUTPUT
      # ======================================================

      - name: Deployment OUTPUT
        shell: bash
        env:
          PAGE_URL: ${{ steps.deployment.outputs.page_url }}

        run: |

          set -euo pipefail

          BASE_URL="${PAGE_URL%/}"


          echo ""
          echo "========================================"
          echo "       CF-IP DEPLOYMENT"
          echo "========================================"
          echo ""

          echo "状态：✅ GitHub Pages 部署成功"
          echo ""

          echo "Pages："
          echo "${BASE_URL}/"
          echo ""

          echo "VLESS TXT："
          echo "${BASE_URL}/all.txt"
          echo ""

          echo "Mihomo YAML："
          echo "${BASE_URL}/all.yaml"
          echo ""

          echo "========================================"


          {
            echo ""
            echo "# ✅ CF-IP 部署成功"
            echo ""

            echo "GitHub Pages 已成功部署。"
            echo ""

            echo "🌐 **Pages：**"
            echo ""
            echo "[打开 Pages](${BASE_URL}/)"
            echo ""

            echo "📄 **VLESS：**"
            echo ""
            echo "[all.txt](${BASE_URL}/all.txt)"
            echo ""

            echo "📄 **Mihomo：**"
            echo ""
            echo "[all.yaml](${BASE_URL}/all.yaml)"

          } >> "$GITHUB_STEP_SUMMARY"
