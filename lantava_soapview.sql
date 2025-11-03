-- phpMyAdmin SQL Dump
-- version 5.2.2
-- https://www.phpmyadmin.net/
--
-- Host: localhost:3306
-- Generation Time: Nov 03, 2025 at 01:35 PM
-- Server version: 10.11.6-MariaDB-0+deb12u1-log
-- PHP Version: 8.4.11

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";
SET FOREIGN_KEY_CHECKS = 0;


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `lantava_soapview`
--

-- --------------------------------------------------------

--
-- Drop existing tables to allow re-running the seed script safely
--

DROP TABLE IF EXISTS `pn_reports`;
DROP TABLE IF EXISTS `pn_visits`;
DROP TABLE IF EXISTS `pn_cases`;
DROP TABLE IF EXISTS `appointments`;
DROP TABLE IF EXISTS `user_clinic_grants`;
DROP TABLE IF EXISTS `patients`;
DROP TABLE IF EXISTS `users`;
DROP TABLE IF EXISTS `clinics`;

--
-- Table structure for table `clinics`
--

CREATE TABLE `clinics` (
  `id` int(11) NOT NULL,
  `code` varchar(20) NOT NULL,
  `name` varchar(200) NOT NULL,
  `address` text DEFAULT NULL,
  `phone` varchar(50) DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `contact_person` varchar(100) DEFAULT NULL,
  `active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT NULL ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `clinics`
--

INSERT INTO `clinics` (`id`, `code`, `name`, `address`, `phone`, `email`, `contact_person`, `active`, `created_at`, `updated_at`) VALUES
(1, 'CL001', 'LANTAVAFIX', '486/2 Moo.3 Saladan, Koh Lanta, Krabi 81150', '098-0946349', 'info@lantavafix.com', 'Suttida Chooluan', 1, '2025-10-30 13:06:38', '2025-11-01 08:02:47'),
(2, 'CL002', 'THONBURI LANTA CLINIC', '486/2 Moo.2 Saladan, Ko Lanta, Krabi 81150', '098-0946349', 'thonburilanta@gmail.com', 'CHAINAKORN.C', 1, '2025-10-30 13:06:38', '2025-11-01 08:03:58'),
(3, 'CL003', 'SOUTH LANTA CLINIC', 'Saladan, Klongthom, Krabi', '02-345-6789', 'partner.b@clinic.com', 'Dr. Williams', 1, '2025-10-30 13:06:38', '2025-11-01 08:04:36');

-- --------------------------------------------------------

--
-- Drop existing trigger to avoid duplicate definition errors
--

DROP TRIGGER IF EXISTS `before_patient_delete`;

--
-- Table structure for table `patients`
--

CREATE TABLE `patients` (
  `id` int(11) NOT NULL,
  `hn` varchar(50) NOT NULL,
  `pt_number` varchar(50) NOT NULL,
  `pid` varchar(13) DEFAULT NULL,
  `passport_no` varchar(50) DEFAULT NULL,
  `title` varchar(20) DEFAULT NULL,
  `first_name` varchar(100) NOT NULL,
  `last_name` varchar(100) NOT NULL,
  `dob` date NOT NULL,
  `gender` enum('M','F','O') DEFAULT NULL,
  `phone` varchar(50) DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `address` text DEFAULT NULL,
  `emergency_contact` varchar(100) DEFAULT NULL,
  `emergency_phone` varchar(50) DEFAULT NULL,
  `diagnosis` text NOT NULL,
  `rehab_goal` text DEFAULT NULL,
  `rehab_goal_other` text DEFAULT NULL,
  `body_area` varchar(200) DEFAULT NULL,
  `frequency` varchar(100) DEFAULT NULL,
  `expected_duration` varchar(100) DEFAULT NULL,
  `doctor_note` text DEFAULT NULL,
  `precaution` text DEFAULT NULL,
  `contraindication` text DEFAULT NULL,
  `medical_history` text DEFAULT NULL,
  `clinic_id` int(11) NOT NULL,
  `created_by` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT NULL ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `patients`
--

INSERT INTO `patients` (`id`, `hn`, `pt_number`, `pid`, `passport_no`, `title`, `first_name`, `last_name`, `dob`, `gender`, `phone`, `email`, `address`, `emergency_contact`, `emergency_phone`, `diagnosis`, `rehab_goal`, `rehab_goal_other`, `body_area`, `frequency`, `expected_duration`, `doctor_note`, `precaution`, `contraindication`, `medical_history`, `clinic_id`, `created_by`, `created_at`, `updated_at`) VALUES
(1, 'PT25001', 'PT20251101171512562', '1810400216716', 'AB1234567', 'Mr.', 'Natthanai', 'Chaibout', '1998-03-23', 'M', '063 080 4644', 'info@lantavafix.com', '96 Moo.1', '0895946517', '0954385392', 'Frozen shoulder', 'Pain reduction, Improve ROM, Improve function', '', 'Shoulder', '2 times/week', '2-4 weeks', '', '', '', 'Motorbike accident', 1, 1, '2025-11-01 10:15:12', NULL),
(2, 'PT25001', 'PT20251101172013744', '1810400216716', 'AB', 'Mr.', 'Natthanai', 'Chaibout', '1998-11-04', 'M', '0630804644', 'info@lantavafix.com', '96 Moo.1', '0895946517', '0954385392', 'Neck pain', 'Pain reduction, Improve ROM, Strengthen muscles, Improve function', '', 'Wrist/Hand', 'Daily', '1-2 weeks', '', '', '', '', 3, 6, '2025-11-01 10:20:13', NULL),
(3, 'PT250368', 'PT20251101200859547', '1810400167167', 'AB12456', 'Mr.', 'Sukho', 'Cheevajit', '1998-11-03', 'M', '063 080 4644', '', '', '', '', 'Joint Ahrititis', 'Pain reduction, Improve ROM, Strengthen muscles, Improve function', '', 'Multiple Areas', '2 times/week', '2-4 weeks', '', '', '', '-', 2, 3, '2025-11-01 13:08:59', NULL);

--
-- Triggers `patients`
--
DELIMITER $$
CREATE TRIGGER `before_patient_delete` BEFORE DELETE ON `patients` FOR EACH ROW BEGIN
    -- Log the deletion (if audit_logs table exists)
    DECLARE audit_table_exists INT;

    SELECT COUNT(*) INTO audit_table_exists
    FROM INFORMATION_SCHEMA.TABLES
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'audit_logs';

    IF audit_table_exists > 0 THEN
        INSERT INTO audit_logs (user_id, action, entity_type, entity_id, old_values, created_at)
        VALUES (
            @current_user_id,
            'DELETE',
            'patient',
            OLD.id,
            JSON_OBJECT(
                'hn', OLD.hn,
                'pt_number', OLD.pt_number,
                'name', CONCAT(OLD.first_name, ' ', OLD.last_name),
                'clinic_id', OLD.clinic_id
            ),
            NOW()
        );
    END IF;
END
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `appointments`
--

CREATE TABLE `appointments` (
  `id` int(11) NOT NULL,
  `patient_id` int(11) NOT NULL,
  `pt_id` int(11) DEFAULT NULL,
  `clinic_id` int(11) NOT NULL,
  `appointment_date` date NOT NULL,
  `start_time` time NOT NULL,
  `end_time` time NOT NULL,
  `status` enum('SCHEDULED','COMPLETED','CANCELLED','NO_SHOW') NOT NULL DEFAULT 'SCHEDULED',
  `appointment_type` varchar(100) DEFAULT NULL,
  `reason` text DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `created_by` int(11) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT NULL ON UPDATE current_timestamp(),
  `cancellation_reason` text DEFAULT NULL,
  `cancelled_at` timestamp NULL DEFAULT NULL,
  `cancelled_by` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `appointments`
--

INSERT INTO `appointments` (`id`, `patient_id`, `pt_id`, `clinic_id`, `appointment_date`, `start_time`, `end_time`, `status`, `appointment_type`, `reason`, `notes`, `created_by`, `created_at`, `updated_at`, `cancellation_reason`, `cancelled_at`, `cancelled_by`) VALUES
(1, 1, 4, 1, '2025-11-03', '10:00:00', '10:45:00', 'SCHEDULED', 'Initial Assessment', 'Shoulder evaluation and plan discussion', 'Bring prior imaging results.', 1, '2025-11-02 09:00:00', NULL, NULL, NULL, NULL),
(2, 2, 5, 3, '2025-11-04', '09:00:00', '10:00:00', 'COMPLETED', 'Treatment Session', 'Neck pain follow up', 'Manual therapy and HEP review.', 4, '2025-11-01 12:00:00', '2025-11-04 10:30:00', NULL, NULL, NULL),
(3, 3, 4, 2, '2025-11-05', '14:00:00', '14:45:00', 'CANCELLED', 'Follow-up', 'Re-assessment request', 'Patient will reschedule after travel.', 5, '2025-11-02 08:10:00', '2025-11-03 11:15:00', 'Patient travelling overseas', '2025-11-03 11:15:00', 1),
(4, 1, 5, 1, '2025-11-07', '16:00:00', '16:45:00', 'NO_SHOW', 'Treatment Session', 'Progress check', 'Marked as no-show after 15 minutes.', 4, '2025-11-05 07:30:00', '2025-11-07 17:15:00', 'Patient did not arrive', '2025-11-07 17:15:00', 4);

-- --------------------------------------------------------

--
-- Table structure for table `pn_cases`
--

CREATE TABLE `pn_cases` (
  `id` int(11) NOT NULL,
  `pn_code` varchar(50) NOT NULL,
  `patient_id` int(11) NOT NULL,
  `diagnosis` text NOT NULL,
  `purpose` text NOT NULL,
  `status` enum('PENDING','ACCEPTED','IN_PROGRESS','COMPLETED','CANCELLED') NOT NULL DEFAULT 'PENDING',
  `source_clinic_id` int(11) NOT NULL,
  `target_clinic_id` int(11) NOT NULL,
  `referring_doctor` varchar(200) DEFAULT NULL,
  `assigned_pt_id` int(11) DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `current_medications` text DEFAULT NULL,
  `allergies` text DEFAULT NULL,
  `pn_precautions` text DEFAULT NULL,
  `pn_contraindications` text DEFAULT NULL,
  `treatment_goals` text DEFAULT NULL,
  `expected_outcomes` text DEFAULT NULL,
  `medical_notes` text DEFAULT NULL,
  `vital_signs` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`vital_signs`)),
  `pain_scale` int(11) DEFAULT NULL,
  `functional_status` text DEFAULT NULL,
  `physio_diagnosis` text DEFAULT NULL,
  `chief_complaint` text DEFAULT NULL,
  `present_history` text DEFAULT NULL,
  `initial_pain_scale` int(11) DEFAULT NULL,
  `assessed_by` int(11) DEFAULT NULL,
  `assessed_at` timestamp NULL DEFAULT NULL,
  `reversal_reason` text DEFAULT NULL,
  `accepted_at` timestamp NULL DEFAULT NULL,
  `completed_at` timestamp NULL DEFAULT NULL,
  `cancelled_at` timestamp NULL DEFAULT NULL,
  `cancellation_reason` text DEFAULT NULL,
  `created_by` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT NULL ON UPDATE current_timestamp(),
  `pt_diagnosis` text DEFAULT NULL COMMENT 'Physiotherapy diagnosis for non-CL001 cases',
  `pt_chief_complaint` text DEFAULT NULL COMMENT 'Chief complaint for non-CL001 cases',
  `pt_present_history` text DEFAULT NULL COMMENT 'Present history for non-CL001 cases',
  `pt_pain_score` int(11) DEFAULT NULL COMMENT 'Pain score 0-10 for non-CL001 cases',
  `is_reversed` tinyint(1) DEFAULT 0,
  `last_reversal_reason` text DEFAULT NULL,
  `last_reversed_at` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `pn_cases`
--

INSERT INTO `pn_cases` (`id`, `pn_code`, `patient_id`, `diagnosis`, `purpose`, `status`, `source_clinic_id`, `target_clinic_id`, `referring_doctor`, `assigned_pt_id`, `notes`, `current_medications`, `allergies`, `pn_precautions`, `pn_contraindications`, `treatment_goals`, `expected_outcomes`, `medical_notes`, `vital_signs`, `pain_scale`, `functional_status`, `physio_diagnosis`, `chief_complaint`, `present_history`, `initial_pain_scale`, `assessed_by`, `assessed_at`, `reversal_reason`, `accepted_at`, `completed_at`, `cancelled_at`, `cancellation_reason`, `created_by`, `created_at`, `updated_at`, `pt_diagnosis`, `pt_chief_complaint`, `pt_present_history`, `pt_pain_score`, `is_reversed`, `last_reversal_reason`, `last_reversed_at`) VALUES
(1, 'PN-20251101192356-2241', 1, 'Frozen shoulder', 's', 'COMPLETED', 1, 1, NULL, NULL, 's', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2025-11-01 12:24:10', '2025-11-01 12:24:34', NULL, NULL, 1, '2025-11-01 12:23:56', '2025-11-01 12:24:34', NULL, NULL, NULL, NULL, 0, NULL, NULL),
(2, 'PN-20251101192516-2934', 2, 'Neck pain', 's', 'COMPLETED', 3, 3, NULL, NULL, 's', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2025-11-01 12:25:32', '2025-11-01 12:25:42', NULL, NULL, 1, '2025-11-01 12:25:16', '2025-11-01 12:25:42', 's', 's', 's', 5, 0, NULL, NULL),
(3, 'PN-20251101200453-4191', 2, 'Neck pain', 'Pain relief', 'ACCEPTED', 3, 1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2025-11-01 13:05:15', NULL, NULL, NULL, 1, '2025-11-01 13:04:53', '2025-11-02 05:08:54', NULL, NULL, NULL, NULL, 0, NULL, NULL),
(4, 'PN-20251101200925-2266', 3, 'Joint Ahrititis', 'Pain relief', 'COMPLETED', 2, 2, NULL, NULL, NULL, '', '', '', '', '', '', '', NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2025-11-01 13:42:30', '2025-11-01 13:58:36', NULL, NULL, 3, '2025-11-01 13:09:25', '2025-11-01 13:58:36', 'Pain and joint stiffness cauesd by joint arthitis', 'pt.มีอาการปวดไหล่ซ้าย P=3/10 และมีอาการยกไหล่ไม่สุด', 'pt.มีอาการปวดไหล่ซ้าย P=3/10 และมีอาการยกไหล่ไม่สุด มาประมาณ 3 เดือน จากการเกิดอุบัติเหตุ', 3, 1, 'เพิ่มรายการรักษา', '2025-11-01 20:57:45'),
(5, 'PN-20251101210329-7770', 3, 'Joint Ahrititis', 'cont. treatment', 'ACCEPTED', 2, 1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2025-11-02 05:08:38', NULL, NULL, NULL, 1, '2025-11-01 14:03:29', '2025-11-02 05:08:46', NULL, NULL, NULL, NULL, 0, NULL, NULL),
(6, 'PN-20251102122223-3153', 3, 'Joint Ahrititis', 'Pain relief', 'ACCEPTED', 2, 1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2025-11-02 05:22:30', NULL, NULL, NULL, 1, '2025-11-02 05:22:23', '2025-11-02 05:28:42', NULL, NULL, NULL, NULL, 0, NULL, NULL),
(7, 'PN-20251102123358-0679', 1, 'Frozen shoulder', 'Pain relief\n', 'ACCEPTED', 1, 1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2025-11-02 05:34:06', NULL, NULL, NULL, 1, '2025-11-02 05:33:58', '2025-11-02 05:34:37', NULL, NULL, NULL, NULL, 0, NULL, NULL),
(8, 'PN-20251102124104-3825', 3, 'Joint Ahrititis', 'pain relief', 'ACCEPTED', 2, 2, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2025-11-02 05:41:22', NULL, NULL, NULL, 1, '2025-11-02 05:41:04', '2025-11-03 03:00:26', 'Testing', 'Testing', 'Testing', 5, 1, 're-edit\\', '2025-11-02 14:41:26');

-- --------------------------------------------------------

--
-- Table structure for table `pn_reports`
--

CREATE TABLE `pn_reports` (
  `id` int(11) NOT NULL,
  `visit_id` int(11) NOT NULL,
  `report_type` enum('INITIAL','PROGRESS','DISCHARGE','SUMMARY') NOT NULL DEFAULT 'PROGRESS',
  `file_path` varchar(500) DEFAULT NULL,
  `file_name` varchar(255) DEFAULT NULL,
  `mime_type` varchar(100) DEFAULT NULL,
  `file_size` int(11) DEFAULT NULL,
  `qr_code` text DEFAULT NULL,
  `report_data` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`report_data`)),
  `created_by` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT NULL ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `pn_visits`
--

CREATE TABLE `pn_visits` (
  `id` int(11) NOT NULL,
  `pn_id` int(11) NOT NULL,
  `visit_no` int(11) NOT NULL,
  `visit_date` date NOT NULL,
  `visit_time` time DEFAULT NULL,
  `status` enum('SCHEDULED','COMPLETED','CANCELLED','NO_SHOW') NOT NULL DEFAULT 'SCHEDULED',
  `chief_complaint` text DEFAULT NULL,
  `subjective` text DEFAULT NULL,
  `objective` text DEFAULT NULL,
  `assessment` text DEFAULT NULL,
  `plan` text DEFAULT NULL,
  `treatment_provided` text DEFAULT NULL,
  `therapist_id` int(11) DEFAULT NULL,
  `duration_minutes` int(11) DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `created_by` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT NULL ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` enum('ADMIN','CLINIC','PT') NOT NULL DEFAULT 'PT',
  `clinic_id` int(11) DEFAULT NULL,
  `first_name` varchar(100) NOT NULL,
  `last_name` varchar(100) NOT NULL,
  `license_number` varchar(50) DEFAULT NULL,
  `phone` varchar(50) DEFAULT NULL,
  `active` tinyint(1) DEFAULT 1,
  `last_login` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT NULL ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `email`, `password_hash`, `role`, `clinic_id`, `first_name`, `last_name`, `license_number`, `phone`, `active`, `last_login`, `created_at`, `updated_at`) VALUES
(1, 'admin@lantavafix.com', '$2a$10$1CnAowBeg3HR0BhEqQAzzuOlCP/6679p/dmprIQjYlBazlQcrRWSi', 'ADMIN', 1, 'System', 'Administrator', NULL, '099-999-9999', 1, '2025-11-03 04:40:44', '2025-10-30 13:06:38', '2025-11-03 04:40:44'),
(2, 'clinic1@pn-app.com', '$2b$10$YourHashedPasswordHere', 'CLINIC', 1, 'Clinic', 'Manager 1', NULL, '099-111-1111', 1, NULL, '2025-10-30 13:06:38', NULL),
(3, 'clinic2@pn-app.com', '$2b$10$ZrCsju4DE/2srmEwjnwHPOjylmTjm3osySJRM7Tj0lULc1BKd2Xvq', 'CLINIC', 2, 'Clinic', 'Manager 2', '', '099-222-2222', 1, '2025-11-02 05:42:33', '2025-10-30 13:06:38', '2025-11-02 05:42:33'),
(4, 'pt1@pn-app.com', '$2b$10$NfSNeqPw6PIEVOYHGf0TA.UNs.eb07qivuXKT69s3iUXQeMIRlMhK', 'PT', 1, 'John', 'Therapist', 'PT12345', '099-333-3333', 1, '2025-11-01 13:36:40', '2025-10-30 13:06:38', '2025-11-01 13:36:40'),
(5, 'pt2@pn-app.com', '$2b$10$Vg5UV2HuJdMCFDliHDwoxOIxY8W5CIYnKT0tGjY5c/D9LNi22XpMO', 'PT', 1, 'Jane', 'Senior PT', 'PT54321', '099-444-4444', 1, '2025-11-01 13:37:03', '2025-10-30 13:06:38', '2025-11-01 13:37:03'),
(6, 'natthanai2341@gmail.com', '$2b$10$41h8gEDRy.TnWS3GmkdeIeYIhkGrv8HWBljBmt/XKvBBY.8AK8x6i', 'CLINIC', 3, 'John', 'Doe', '', '', 1, '2025-11-01 10:19:36', '2025-10-31 07:52:02', '2025-11-01 10:19:36');

-- --------------------------------------------------------

--
-- Table structure for table `user_clinic_grants`
--

CREATE TABLE `user_clinic_grants` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `clinic_id` int(11) NOT NULL,
  `granted_by` int(11) NOT NULL,
  `granted_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `user_clinic_grants`
--

INSERT INTO `user_clinic_grants` (`id`, `user_id`, `clinic_id`, `granted_by`, `granted_at`) VALUES
(1, 4, 2, 1, '2025-10-30 13:06:38'),
(2, 4, 3, 1, '2025-10-30 13:06:38'),
(3, 5, 2, 1, '2025-10-30 13:06:38');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `clinics`
--
ALTER TABLE `clinics`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `code` (`code`),
  ADD KEY `idx_clinic_active` (`active`),
  ADD KEY `idx_clinic_code` (`code`);

--
-- Indexes for table `patients`
--
ALTER TABLE `patients`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `pt_number` (`pt_number`),
  ADD KEY `created_by` (`created_by`),
  ADD KEY `idx_patient_hn` (`hn`),
  ADD KEY `idx_patient_pt_number` (`pt_number`),
  ADD KEY `idx_patient_pid` (`pid`),
  ADD KEY `idx_patient_name` (`first_name`,`last_name`),
  ADD KEY `idx_patient_clinic` (`clinic_id`);

--
-- Indexes for table `appointments`
--
ALTER TABLE `appointments`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_appointments_patient` (`patient_id`),
  ADD KEY `idx_appointments_pt` (`pt_id`),
  ADD KEY `idx_appointments_clinic` (`clinic_id`),
  ADD KEY `idx_appointments_date` (`appointment_date`),
  ADD KEY `idx_appointments_status` (`status`);

--
-- Indexes for table `pn_cases`
--
ALTER TABLE `pn_cases`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `pn_code` (`pn_code`),
  ADD KEY `created_by` (`created_by`),
  ADD KEY `idx_pn_code` (`pn_code`),
  ADD KEY `idx_pn_patient` (`patient_id`),
  ADD KEY `idx_pn_status` (`status`),
  ADD KEY `idx_pn_source_clinic` (`source_clinic_id`),
  ADD KEY `idx_pn_target_clinic` (`target_clinic_id`),
  ADD KEY `idx_pn_created_at` (`created_at`),
  ADD KEY `idx_pn_assigned_pt` (`assigned_pt_id`),
  ADD KEY `idx_pn_assessed_by` (`assessed_by`),
  ADD KEY `idx_pn_assessed_at` (`assessed_at`);

--
-- Indexes for table `pn_reports`
--
ALTER TABLE `pn_reports`
  ADD PRIMARY KEY (`id`),
  ADD KEY `created_by` (`created_by`),
  ADD KEY `idx_report_visit` (`visit_id`),
  ADD KEY `idx_report_type` (`report_type`),
  ADD KEY `idx_report_created_at` (`created_at`);

--
-- Indexes for table `pn_visits`
--
ALTER TABLE `pn_visits`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_pn_visit_no` (`pn_id`,`visit_no`),
  ADD KEY `therapist_id` (`therapist_id`),
  ADD KEY `created_by` (`created_by`),
  ADD KEY `idx_visit_pn` (`pn_id`),
  ADD KEY `idx_visit_date` (`visit_date`),
  ADD KEY `idx_visit_status` (`status`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`),
  ADD KEY `idx_user_email` (`email`),
  ADD KEY `idx_user_role` (`role`),
  ADD KEY `idx_user_clinic` (`clinic_id`);

--
-- Indexes for table `user_clinic_grants`
--
ALTER TABLE `user_clinic_grants`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_user_clinic` (`user_id`,`clinic_id`),
  ADD KEY `granted_by` (`granted_by`),
  ADD KEY `idx_grant_user` (`user_id`),
  ADD KEY `idx_grant_clinic` (`clinic_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `clinics`
--
ALTER TABLE `clinics`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `patients`
--
ALTER TABLE `patients`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `appointments`
--
ALTER TABLE `appointments`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT for table `pn_cases`
--
ALTER TABLE `pn_cases`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- AUTO_INCREMENT for table `pn_reports`
--
ALTER TABLE `pn_reports`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `pn_visits`
--
ALTER TABLE `pn_visits`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `user_clinic_grants`
--
ALTER TABLE `user_clinic_grants`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `patients`
--
ALTER TABLE `patients`
  ADD CONSTRAINT `patients_ibfk_1` FOREIGN KEY (`clinic_id`) REFERENCES `clinics` (`id`),
  ADD CONSTRAINT `patients_ibfk_2` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`);

--
-- Constraints for table `appointments`
--
ALTER TABLE `appointments`
  ADD CONSTRAINT `appointments_patient_fk` FOREIGN KEY (`patient_id`) REFERENCES `patients` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `appointments_pt_fk` FOREIGN KEY (`pt_id`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `appointments_clinic_fk` FOREIGN KEY (`clinic_id`) REFERENCES `clinics` (`id`),
  ADD CONSTRAINT `appointments_created_by_fk` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `appointments_cancelled_by_fk` FOREIGN KEY (`cancelled_by`) REFERENCES `users` (`id`) ON DELETE SET NULL;

--
-- Constraints for table `pn_cases`
--
ALTER TABLE `pn_cases`
  ADD CONSTRAINT `fk_pn_assessor` FOREIGN KEY (`assessed_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_pn_patient` FOREIGN KEY (`patient_id`) REFERENCES `patients` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `pn_cases_ibfk_2` FOREIGN KEY (`source_clinic_id`) REFERENCES `clinics` (`id`),
  ADD CONSTRAINT `pn_cases_ibfk_3` FOREIGN KEY (`target_clinic_id`) REFERENCES `clinics` (`id`),
  ADD CONSTRAINT `pn_cases_ibfk_4` FOREIGN KEY (`assigned_pt_id`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `pn_cases_ibfk_5` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`);

--
-- Constraints for table `pn_reports`
--
ALTER TABLE `pn_reports`
  ADD CONSTRAINT `pn_reports_ibfk_1` FOREIGN KEY (`visit_id`) REFERENCES `pn_visits` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `pn_reports_ibfk_2` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`);

--
-- Constraints for table `pn_visits`
--
ALTER TABLE `pn_visits`
  ADD CONSTRAINT `fk_visit_pn` FOREIGN KEY (`pn_id`) REFERENCES `pn_cases` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `pn_visits_ibfk_1` FOREIGN KEY (`pn_id`) REFERENCES `pn_cases` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `pn_visits_ibfk_2` FOREIGN KEY (`therapist_id`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `pn_visits_ibfk_3` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`);

--
-- Constraints for table `users`
--
ALTER TABLE `users`
  ADD CONSTRAINT `users_ibfk_1` FOREIGN KEY (`clinic_id`) REFERENCES `clinics` (`id`) ON DELETE SET NULL;

--
-- Constraints for table `user_clinic_grants`
--
ALTER TABLE `user_clinic_grants`
  ADD CONSTRAINT `user_clinic_grants_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `user_clinic_grants_ibfk_2` FOREIGN KEY (`clinic_id`) REFERENCES `clinics` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `user_clinic_grants_ibfk_3` FOREIGN KEY (`granted_by`) REFERENCES `users` (`id`);
SET FOREIGN_KEY_CHECKS = 1;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
