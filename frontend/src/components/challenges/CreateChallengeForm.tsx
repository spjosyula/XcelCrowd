"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Alert } from "@/components/ui/alert";
import { Challenge, ChallengeDifficulty, ChallengeVisibility } from "@/types/challenge";
import { ChallengeService } from "@/services/challenge.service";

// Schema for challenge creation form matching backend validation
const createChallengeSchema = z.object({
  title: z.string()
    .min(1, "Title is required")
    .max(100, "Title cannot exceed 100 characters")
    .trim(),

  description: z.string()
    .min(1, "Description is required")
    .trim(),

  requirements: z.array(z.string().trim())
    .min(1, "At least one requirement is needed"),

  resources: z.array(z.string().trim())
    .optional(),

  rewards: z.string().trim().optional(),

  deadline: z.string()
    .refine(val => new Date(val) > new Date(), {
      message: "Deadline must be in the future"
    }),

  difficulty: z.enum(Object.values(ChallengeDifficulty) as [string, ...string[]]),

  category: z.array(z.string().trim())
    .min(1, "At least one category is required"),

  maxParticipants: z.number().int().min(1).optional(),

  tags: z.array(z.string().trim()).optional(),

  maxApprovedSolutions: z.number().int().min(1).default(5),

  visibility: z.enum(Object.values(ChallengeVisibility) as [string, ...string[]])
    .default(ChallengeVisibility.PUBLIC),

  allowedInstitutions: z.array(z.string().trim())
    .optional(),

  isCompanyVisible: z.boolean()
    .default(true),
    
  shouldPublish: z.boolean().optional(),
  
  autoCloseOnDeadline: z.boolean().default(true)
});

// Create a type from the zod schema
type CreateChallengeFormData = z.infer<typeof createChallengeSchema>;

// Category options for the form
const CATEGORY_OPTIONS = [
  "Software Development",
  "Data Science",
  "Artificial Intelligence",
  "Machine Learning",
  "Web Development",
  "Mobile App Development",
  "UI/UX Design",
  "Cloud Computing",
  "Cybersecurity",
  "DevOps",
  "Blockchain",
  "IoT",
  "Quantum Computing",
  "Robotics",
  "Business Analysis",
  "Project Management"
];

export function CreateChallengeForm() {
  const router = useRouter();
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<boolean>(false);
  const [successMessage, setSuccessMessage] = useState<string>("");
  const [newRequirement, setNewRequirement] = useState("");
  const [newResource, setNewResource] = useState("");
  const [newTag, setNewTag] = useState("");
  const [newInstitution, setNewInstitution] = useState("");

  // Form validation and state management with react-hook-form
  const {
    register,
    handleSubmit,
    watch,
    setValue,
    formState: { errors },
    reset
  } = useForm<CreateChallengeFormData>({
    resolver: zodResolver(createChallengeSchema),
    defaultValues: {
      title: "",
      description: "",
      requirements: [],
      resources: [],
      rewards: "",
      deadline: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split("T")[0], // 30 days from now
      difficulty: ChallengeDifficulty.INTERMEDIATE,
      category: [],
      maxParticipants: 50,
      tags: [],
      maxApprovedSolutions: 5,
      visibility: ChallengeVisibility.PUBLIC,
      allowedInstitutions: [],
      isCompanyVisible: true,
      shouldPublish: false,
      autoCloseOnDeadline: true
    }
  });

  // Watch for visibility changes to conditionally render institution fields
  const selectedVisibility = watch("visibility");
  const requirements = watch("requirements");
  const resources = watch("resources");
  const categories = watch("category");
  const tags = watch("tags");
  const allowedInstitutions = watch("allowedInstitutions");

  // Form submission handler
  const onSubmit = async (data: CreateChallengeFormData) => {
    setIsSubmitting(true);
    setError("");
    setSuccess(false);
    
    // Get publish flag from the form data
    const shouldPublish = data.shouldPublish || false;
    
    // Prepare challenge data object
    const challengeData: Partial<Challenge> = {
      title: data.title,
      description: data.description,
      requirements: data.requirements || [],
      resources: data.resources,
      difficulty: data.difficulty as ChallengeDifficulty,
      deadline: data.deadline ? new Date(data.deadline).toISOString() : undefined,
      category: data.category || [],
      tags: data.tags || [],
      visibility: data.visibility as ChallengeVisibility,
      allowedInstitutions: data.visibility === 'PRIVATE' ? data.allowedInstitutions : undefined,
      maxParticipants: data.maxParticipants ? Number(data.maxParticipants) : undefined,
      maxApprovedSolutions: data.maxApprovedSolutions ? Number(data.maxApprovedSolutions) : undefined,
      isCompanyVisible: data.isCompanyVisible,
      rewards: data.rewards?.trim().length ? data.rewards : undefined,
      autoCloseOnDeadline: data.autoCloseOnDeadline
    };

    try {
      console.log("Submitting challenge data:", challengeData);
      const challenge = await ChallengeService.createChallenge(challengeData);
      console.log("Challenge created successfully:", challenge);
      
      // If shouldPublish is true, redirect to publish preview page
      if (shouldPublish) {
        setSuccessMessage("Challenge created! Redirecting to publish preview...");
        setTimeout(() => {
          router.push(`/challenge/publish?id=${challenge._id}`);
        }, 1000);
      } else {
        setSuccessMessage("Challenge saved as draft. Publish it when you're ready.");
        
        // Redirect to the challenge page after successful creation
        setTimeout(() => {
          console.log("Redirecting to challenge page:", `/challenge/${challenge._id}`);
          router.push(`/challenge/${challenge._id}`);
        }, 1500);
      }
      
      setSuccess(true);
      reset();
    } catch (err: any) {
      console.error("Challenge creation failed:", err);
      
      // Extract error message
      if (err.isHandled) {
        // This is a handled error from our service
        setError(err.message);
      } else if (err.response?.data?.message) {
        setError(err.response.data.message);
      } else if (err.message) {
        setError(err.message);
      } else {
        setError("Failed to create challenge. Please try again.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  // Handlers for saving as draft vs publishing
  const handleSaveAsDraft = () => {
    setValue("shouldPublish", false);
  };

  const handlePublish = () => {
    setValue("shouldPublish", true);
  };

  // Array field handlers
  const addRequirement = () => {
    if (newRequirement.trim()) {
      setValue("requirements", [...requirements, newRequirement.trim()]);
      setNewRequirement("");
    }
  };

  const removeRequirement = (index: number) => {
    setValue(
      "requirements",
      requirements.filter((_, i) => i !== index)
    );
  };

  const addResource = () => {
    if (newResource.trim()) {
      setValue("resources", [...(resources || []), newResource.trim()]);
      setNewResource("");
    }
  };

  const removeResource = (index: number) => {
    setValue(
      "resources",
      (resources || []).filter((_, i) => i !== index)
    );
  };

  const addCategory = (category: string) => {
    if (!categories.includes(category)) {
      setValue("category", [...categories, category]);
    }
  };

  const removeCategory = (category: string) => {
    setValue(
      "category",
      categories.filter((c) => c !== category)
    );
  };

  const addTag = () => {
    if (newTag.trim() && (!tags || !tags.includes(newTag.trim()))) {
      setValue("tags", [...(tags || []), newTag.trim()]);
      setNewTag("");
    }
  };

  const removeTag = (index: number) => {
    setValue(
      "tags",
      (tags || []).filter((_, i) => i !== index)
    );
  };

  const addInstitution = () => {
    if (newInstitution.trim() && 
       (!allowedInstitutions || !allowedInstitutions.includes(newInstitution.trim()))) {
      setValue("allowedInstitutions", [...(allowedInstitutions || []), newInstitution.trim()]);
      setNewInstitution("");
    }
  };

  const removeInstitution = (index: number) => {
    setValue(
      "allowedInstitutions",
      (allowedInstitutions || []).filter((_, i) => i !== index)
    );
  };

  return (
    <>
      {error && (
        <Alert variant="destructive" className="mb-6">
          {error}
        </Alert>
      )}
      
      {success && (
        <Alert variant="default" className="mb-6 bg-green-50 border-green-200 text-green-800">
          {successMessage}
        </Alert>
      )}
      
      <Card className="p-6">
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
          {/* Title */}
          <div className="space-y-2">
            <label htmlFor="title" className="block text-sm font-medium">
              Title *
            </label>
            <input
              id="title"
              type="text"
              className="w-full p-2 border rounded-md"
              placeholder="Enter challenge title"
              {...register("title")}
            />
            {errors.title && (
              <p className="text-red-500 text-sm">{errors.title.message}</p>
            )}
          </div>
          
          {/* Description */}
          <div className="space-y-2">
            <label htmlFor="description" className="block text-sm font-medium">
              Description *
            </label>
            <textarea
              id="description"
              className="w-full p-2 border rounded-md h-32"
              placeholder="Describe the challenge in detail"
              {...register("description")}
            />
            {errors.description && (
              <p className="text-red-500 text-sm">{errors.description.message}</p>
            )}
          </div>
          
          {/* Requirements */}
          <div className="space-y-2">
            <label htmlFor="requirements" className="block text-sm font-medium">
              Requirements *
            </label>
            <div className="flex gap-2">
              <input
                id="newRequirement"
                type="text"
                className="flex-1 p-2 border rounded-md"
                placeholder="Add a requirement"
                value={newRequirement}
                onChange={(e) => setNewRequirement(e.target.value)}
              />
              <Button type="button" onClick={addRequirement}>
                Add
              </Button>
            </div>
            {errors.requirements && (
              <p className="text-red-500 text-sm">{errors.requirements.message}</p>
            )}
            <div className="mt-2">
              {requirements?.map((req, index) => (
                <div key={index} className="flex items-center gap-2 mb-2">
                  <div className="flex-1 p-2 bg-gray-100 rounded-md">{req}</div>
                  <Button
                    type="button"
                    variant="destructive"
                    size="sm"
                    onClick={() => removeRequirement(index)}
                  >
                    Remove
                  </Button>
                </div>
              ))}
            </div>
          </div>
          
          {/* Resources (Optional) */}
          <div className="space-y-2">
            <label htmlFor="resources" className="block text-sm font-medium">
              Resources (Optional)
            </label>
            <div className="flex gap-2">
              <input
                id="newResource"
                type="text"
                className="flex-1 p-2 border rounded-md"
                placeholder="Add a resource URL or description"
                value={newResource}
                onChange={(e) => setNewResource(e.target.value)}
              />
              <Button type="button" onClick={addResource}>
                Add
              </Button>
            </div>
            <div className="mt-2">
              {resources?.map((resource, index) => (
                <div key={index} className="flex items-center gap-2 mb-2">
                  <div className="flex-1 p-2 bg-gray-100 rounded-md">{resource}</div>
                  <Button
                    type="button"
                    variant="destructive"
                    size="sm"
                    onClick={() => removeResource(index)}
                  >
                    Remove
                  </Button>
                </div>
              ))}
            </div>
          </div>
          
          {/* Rewards (Optional) */}
          <div className="space-y-2">
            <label htmlFor="rewards" className="block text-sm font-medium">
              Rewards (Optional)
            </label>
            <input
              id="rewards"
              type="text"
              className="w-full p-2 border rounded-md"
              placeholder="Describe rewards for successful solutions"
              {...register("rewards")}
            />
          </div>
          
          {/* Deadline */}
          <div className="space-y-2">
            <label htmlFor="deadline" className="block text-sm font-medium">
              Deadline *
            </label>
            <input
              id="deadline"
              type="date"
              className="w-full p-2 border rounded-md"
              {...register("deadline")}
            />
            {errors.deadline && (
              <p className="text-red-500 text-sm">{errors.deadline.message}</p>
            )}
          </div>
          
          {/* Difficulty */}
          <div className="space-y-2">
            <label htmlFor="difficulty" className="block text-sm font-medium">
              Difficulty *
            </label>
            <select
              id="difficulty"
              className="w-full p-2 border rounded-md"
              {...register("difficulty")}
            >
              {Object.values(ChallengeDifficulty).map((difficulty) => (
                <option key={difficulty} value={difficulty}>
                  {difficulty.charAt(0).toUpperCase() + difficulty.slice(1)}
                </option>
              ))}
            </select>
            {errors.difficulty && (
              <p className="text-red-500 text-sm">{errors.difficulty.message}</p>
            )}
          </div>
          
          {/* Categories */}
          <div className="space-y-2">
            <label className="block text-sm font-medium">
              Categories *
            </label>
            <div className="grid grid-cols-2 gap-2 md:grid-cols-3 lg:grid-cols-4">
              {CATEGORY_OPTIONS.map((category) => (
                <div key={category} className="flex items-center">
                  <input
                    type="checkbox"
                    id={`category-${category}`}
                    className="mr-2"
                    checked={categories.includes(category)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        addCategory(category);
                      } else {
                        removeCategory(category);
                      }
                    }}
                  />
                  <label htmlFor={`category-${category}`} className="text-sm">
                    {category}
                  </label>
                </div>
              ))}
            </div>
            {errors.category && (
              <p className="text-red-500 text-sm">{errors.category.message}</p>
            )}
            <div className="mt-2 flex flex-wrap gap-2">
              {categories.map((cat) => (
                <span
                  key={cat}
                  className="bg-blue-100 text-blue-800 px-2 py-1 rounded-md text-sm"
                >
                  {cat}
                </span>
              ))}
            </div>
          </div>
          
          {/* Maximum Participants */}
          <div className="space-y-2">
            <label htmlFor="maxParticipants" className="block text-sm font-medium">
              Maximum Participants (Optional)
            </label>
            <input
              id="maxParticipants"
              type="number"
              min="1"
              className="w-full p-2 border rounded-md"
              placeholder="Leave empty for unlimited"
              {...register("maxParticipants", { valueAsNumber: true })}
            />
          </div>
          
          {/* Tags */}
          <div className="space-y-2">
            <label htmlFor="tags" className="block text-sm font-medium">
              Tags (Optional)
            </label>
            <div className="flex gap-2">
              <input
                id="newTag"
                type="text"
                className="flex-1 p-2 border rounded-md"
                placeholder="Add a tag"
                value={newTag}
                onChange={(e) => setNewTag(e.target.value)}
              />
              <Button type="button" onClick={addTag}>
                Add
              </Button>
            </div>
            <div className="mt-2 flex flex-wrap gap-2">
              {tags?.map((tag, index) => (
                <div
                  key={index}
                  className="bg-gray-100 px-3 py-1 rounded-full flex items-center gap-2"
                >
                  <span>{tag}</span>
                  <button
                    type="button"
                    className="text-red-500 font-bold"
                    onClick={() => removeTag(index)}
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          </div>
          
          {/* Max Approved Solutions */}
          <div className="space-y-2">
            <label htmlFor="maxApprovedSolutions" className="block text-sm font-medium">
              Maximum Approved Solutions
            </label>
            <input
              id="maxApprovedSolutions"
              type="number"
              min="1"
              className="w-full p-2 border rounded-md"
              {...register("maxApprovedSolutions", { valueAsNumber: true })}
            />
          </div>
          
          {/* Visibility */}
          <div className="space-y-2">
            <label htmlFor="visibility" className="block text-sm font-medium">
              Visibility
            </label>
            <select
              id="visibility"
              className="w-full p-2 border rounded-md"
              {...register("visibility")}
            >
              <option value={ChallengeVisibility.PUBLIC}>Public (visible to all students)</option>
              <option value={ChallengeVisibility.PRIVATE}>Private (visible to selected institutions)</option>
              <option value={ChallengeVisibility.ANONYMOUS}>Anonymous (company identity hidden)</option>
            </select>
          </div>
          
          {/* Allowed Institutions (only for private visibility) */}
          {selectedVisibility === ChallengeVisibility.PRIVATE && (
            <div className="space-y-2">
              <label htmlFor="allowedInstitutions" className="block text-sm font-medium">
                Allowed Institutions *
              </label>
              <div className="flex gap-2">
                <input
                  id="newInstitution"
                  type="text"
                  className="flex-1 p-2 border rounded-md"
                  placeholder="Add an institution"
                  value={newInstitution}
                  onChange={(e) => setNewInstitution(e.target.value)}
                />
                <Button type="button" onClick={addInstitution}>
                  Add
                </Button>
              </div>
              {selectedVisibility === ChallengeVisibility.PRIVATE && 
               errors.allowedInstitutions && (
                <p className="text-red-500 text-sm">
                  {errors.allowedInstitutions.message || "At least one institution is required for private challenges"}
                </p>
              )}
              <div className="mt-2">
                {allowedInstitutions?.map((inst, index) => (
                  <div key={index} className="flex items-center gap-2 mb-2">
                    <div className="flex-1 p-2 bg-gray-100 rounded-md">{inst}</div>
                    <Button
                      type="button"
                      variant="destructive"
                      size="sm"
                      onClick={() => removeInstitution(index)}
                    >
                      Remove
                    </Button>
                  </div>
                ))}
              </div>
            </div>
          )}
          
          {/* Is Company Visible (only for public and private visibility) */}
          {selectedVisibility !== ChallengeVisibility.ANONYMOUS && (
            <div className="space-y-2">
              <div className="flex items-center">
                <input
                  id="isCompanyVisible"
                  type="checkbox"
                  className="mr-2"
                  {...register("isCompanyVisible")}
                />
                <label htmlFor="isCompanyVisible" className="text-sm font-medium">
                  Show company information to students
                </label>
              </div>
            </div>
          )}
          
          {/* Auto Close On Deadline */}
          <div className="space-y-2">
            <div className="flex items-center">
              <input
                id="autoCloseOnDeadline"
                type="checkbox"
                className="mr-2"
                {...register("autoCloseOnDeadline")}
              />
              <label htmlFor="autoCloseOnDeadline" className="text-sm font-medium">
                Auto close on deadline
              </label>
            </div>
            <p className="text-sm text-gray-500">
              When enabled, the challenge will automatically close when the deadline is reached.
              Disable this to keep the challenge open for submissions past the deadline.
            </p>
          </div>
          
          {/* Submit Buttons */}
          <div className="flex justify-end gap-4">
            <Button
              type="button"
              variant="outline"
              onClick={() => router.back()}
              disabled={isSubmitting}
            >
              Cancel
            </Button>
            
            <Button
              type="submit"
              variant="secondary"
              disabled={isSubmitting}
              className="min-w-[150px]"
              onClick={handleSaveAsDraft}
            >
              {isSubmitting ? (
                <div className="flex items-center gap-2">
                  <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Saving...
                </div>
              ) : (
                "Save as Draft"
              )}
            </Button>

            <Button
              type="submit"
              variant="royal"
              disabled={isSubmitting}
              className="min-w-[150px]"
              onClick={handlePublish}
            >
              {isSubmitting ? (
                <div className="flex items-center gap-2">
                  <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Publishing...
                </div>
              ) : (
                "Publish Challenge"
              )}
            </Button>
          </div>
        </form>
      </Card>
    </>
  );
} 