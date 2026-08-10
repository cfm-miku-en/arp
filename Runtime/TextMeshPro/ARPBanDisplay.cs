// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

#if ARP_TMP
using System.Collections;
using TMPro;
using UnityEngine;

namespace ARP
{
    // Renders whatever the server said into a TMP_Text. Deliberately a separate
    // component rather than a field on ARPManager: the manager stays free of UI types,
    // so a project without TextMeshPro still compiles and a dev with their own UI can
    // ignore this entirely and bind the UnityEvents themselves.
    //
    // TMP_Text is the abstract base, so this works with both TextMeshProUGUI on a
    // canvas and TextMeshPro in world space - which matters in VR, where a canvas
    // overlay is usually the wrong choice.
    [AddComponentMenu("ARP/ARP Ban Display")]
    public sealed class ARPBanDisplay : MonoBehaviour
    {
        [Tooltip("Where the message is written. Works with TextMeshProUGUI or the " +
                 "world-space TextMeshPro component.")]
        [SerializeField] private TMP_Text target;

        [Tooltip("Optional. Enabled when there is something to show, disabled otherwise. " +
                 "Leave empty if your panel is always visible.")]
        [SerializeField] private GameObject panel;

        [Tooltip("Leave empty to find the ARPManager in the scene automatically.")]
        [SerializeField] private ARPManager manager;

        [Header("What to show")]
        [SerializeField] private bool showBans = true;

        [Tooltip("Show integrity failures too. These mean the binary is wrong rather " +
                 "than the player being banned, so the wording should differ.")]
        [SerializeField] private bool showIntegrityFailures = false;

        [TextArea(2, 4)]
        [Tooltip("Shown for an integrity failure. {{reason}} is replaced with the " +
                 "server's detail.")]
        [SerializeField] private string integrityMessage =
            "A problem was found with your game files. Please reinstall from the store.";

        [Header("Lockout")]
        [Tooltip("Quit the app after showing the message.\n\n" +
                 "Cosmetic only. The real ban is already applied server-side and holds " +
                 "whether or not the client cooperates - a patched client simply will not " +
                 "run this. Never treat it as the enforcement mechanism.")]
        [SerializeField] private bool quitAfterDelay = false;

        [SerializeField, Range(1f, 60f)] private float quitDelaySeconds = 10f;

        private void Awake()
        {
            if (panel != null) panel.SetActive(false);
        }

        private void OnEnable()
        {
            if (manager == null)
            {
#if UNITY_2023_1_OR_NEWER
                manager = FindAnyObjectByType<ARPManager>();
#else
                manager = FindObjectOfType<ARPManager>();
#endif
            }

            if (manager == null)
            {
                Debug.LogWarning("[ARP] ARPBanDisplay found no ARPManager, so nothing will " +
                                 "ever be shown. Assign one, or put this on the same scene.");
                return;
            }

            if (showBans) manager.OnBanConfirmed.AddListener(Show);
            if (showIntegrityFailures) manager.OnIntegrityCheckFailed.AddListener(ShowIntegrity);
        }

        private void OnDisable()
        {
            if (manager == null) return;

            manager.OnBanConfirmed.RemoveListener(Show);
            manager.OnIntegrityCheckFailed.RemoveListener(ShowIntegrity);
        }

        private void ShowIntegrity(string reason)
        {
            Show(integrityMessage.Replace("{{reason}}", reason ?? string.Empty));
        }

        public void Show(string message)
        {
            if (string.IsNullOrEmpty(message)) return;

            if (target != null) target.SetText(message);
            else Debug.LogWarning("[ARP] ARPBanDisplay has no target TMP_Text assigned: " + message);

            if (panel != null) panel.SetActive(true);

            if (quitAfterDelay) StartCoroutine(QuitAfterDelay());
        }

        private IEnumerator QuitAfterDelay()
        {
            yield return new WaitForSecondsRealtime(quitDelaySeconds);
            Application.Quit();
        }
    }
}
#endif
